<?php

namespace SimPro\Api;

use \Eher\OAuth\Consumer as OAuthConsumer;
use \Eher\OAuth\Token as OAuthToken;
use \Eher\OAuth\Request as OAuthRequest;
use \Eher\OAuth\SignatureMethod as OAuthSignatureMethod;

/**
 */
class Client implements \Psr\Log\LoggerAwareInterface {

    /**@#+
     * @const Endpoint Constants
     */
    const API_URL = 'https://%s/api/';

    const REQUEST_TOKEN_URL = 'https://%s/api/oauth/request_token.php';

    const ACCESS_TOKEN_URL = 'https://%s/api/oauth/access_token.php';

    const AUTHORIZE_URL = 'https://%s/oauth/authorize.php?oauth_token=%s';

    const OAUTH_REALM = 'simPROAPI';
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var \Tivoka\Client\Connection
     */
    private $connection;

    /**
     * @var \Eher\OAuth\Consumer
     */
    private $consumer;

    /**
     * @var \Eher\OAuth\Token
     */
    private $accessToken;

    /**
     * @var \Eher\OAuth\SignatureMethod
     */
    private $signatureMethod;
    /**
     * @var string
     */
    private $host;


    /**
     * @param string                       $host The host name of the simPRO installation. If a port is required, it can be in the format '{hostName}:{port}'
     * @param \Eher\OAuth\Consumer         $consumer
     * @param \Eher\OAuth\Token            $accessToken
     *
     * @throws \Exception
     */
    public function __construct($host, OAuthConsumer $consumer, OAuthToken $accessToken = null, OAuthSignatureMethod $signatureMethod = null){
        // check the host name
        if (!$this->isValidHost($host)){
            throw new \Exception("Invalid host: '{$host}'");
        }
        // set the consumer, token & signature method
        $this->consumer = $consumer;
        $this->accessToken = $accessToken;
        if ($signatureMethod === null){
            $signatureMethod = new \Eher\OAuth\HmacSha1();
        }
        $this->signatureMethod = $signatureMethod;
        // set the host
        $this->host = $host;
        // generate the API URL from the host
        $url = sprintf(self::API_URL, $this->host);
        // create a JSON-RPC client connection to the url
        $this->connection = \Tivoka\Client::connect($url);
        // configure the specification setting
        $this->connection->useSpec(1.0);
        // Default the logger to null - can be overwritten using setLogger
        $this->logger = new \Psr\Log\NullLogger();
    }


    /**
     * @param string $method
     * @param string $args
     * @return mixed
     *
     * @throws \Tivoka\Exception\RemoteProcedureException
     */
    public function __call($method, $args){
        // log the incoming call
        $this->logger->info("Performing Request", array("host"=>$this->host, "method"=>$method, "args"=>$args));
        // reset the headers
        $this->connection->headers = array();
        // Configure the OAuth request & Sign
        $oAuthRequest = OAuthRequest::from_consumer_and_token($this->consumer, $this->accessToken, 'POST', sprintf(self::API_URL, $this->host));
        $oAuthRequest->sign_request($this->signatureMethod, $this->consumer, $this->accessToken);
        // get the signature header - and set on the connection
        $header = $oAuthRequest->to_header(self::OAUTH_REALM);
        list($label, $value) = explode(':', $header, 2);
        $this->connection->setHeader($label,$value);
        // perform the JSON-RPC Request
        $rpcRequest = new \Tivoka\Client\Request($method, $args);
        $this->connection->send($rpcRequest);
        // check for errors
        if($rpcRequest->isError()) {
            $this->logger->error("Request Failed", array("host"=>$this->host, "method"=>$method, "args"=>$args, "errorMessage"=>$rpcRequest->errorMessage));
            throw new \Tivoka\Exception\RemoteProcedureException($rpcRequest->errorMessage, $rpcRequest->error);
        }
        // return the result if successul
        return $rpcRequest->result;
    }


    /**
     * Validates host name, with port number attached
     *
     * @link http://stackoverflow.com/questions/1755144/how-to-validate-host-name-in-php
     *
     * @param $hostName
     *
     * @return bool
     */
    private function isValidHost($hostName)
    {
        // check for presence of 'Port'
        $hostPieces = explode(':', $hostName, 2);
        if (count($hostPieces) > 1){
            $hostName = $hostPieces[0];
            if (!preg_match('/^\d+$/',$hostPieces[1])){
                return false;
            }
        }
        // check host portion is valid
        $hostPieces = explode(".",$hostName);
        foreach($hostPieces as $piece)
        {
            if (!preg_match('/^[a-z\d][a-z\d-]{0,62}$/i', $piece) || preg_match('/-$/', $piece) )
            {
                return false;
            }
        }
        return true;
    }


    /**
     * @param string $callbackUrl
     * @return \Eher\OAuth\Token
     * @throws \Exception
     */
    public function getRequestToken($callbackUrl = 'oob'){
        $this->logger->info("Obtaining Request Token", array("host"=>$this->host, "callbackUrl"=>$callbackUrl));
        // create the URL for the Request Token Endpoint
        $url = sprintf(self::REQUEST_TOKEN_URL, $this->host);
        // create an OAuth Request- configure with local parameters
        $oAuthRequest = OAuthRequest::from_consumer_and_token($this->consumer, null, 'GET', $url);
        $oAuthRequest->set_parameter('oauth_callback',$callbackUrl);
        $oAuthRequest->sign_request($this->signatureMethod, $this->consumer, null);
        // Perform request & Retrieve result
        $headers = array($oAuthRequest->to_header(), 'Accept: application/x-www-form-urlencoded');
        $resultString = $this->performRequest($url, 'GET', $headers);
        // parse the result string (should be www-form-urlencoded
        parse_str($resultString, $result);
        // detect problems
        if (isset($result['oauth_problem'])){
            $this->logger->error("Failed to obtain Request Token", array("host"=>$this->host, "callbackUrl"=>$callbackUrl, "problem"=> $result['oauth_problem']));
            throw new \Exception("Failed to retrieve Request Token because: {$result['oauth_problem']}");
        }
        if (!isset($result['oauth_token']) || !isset($result['oauth_token_secret']) || !isset($result['oauth_callback_confirmed'])){
            $this->logger->error("Failed to obtain Request Token", array("host"=>$this->host, "callbackUrl"=>$callbackUrl));
            throw new \Exception("Failed to retrieve Request Token.");
        }
        // return the token
        return new OAuthToken($result['oauth_token'], $result['oauth_token_secret']);
    }


    /**
     * @param \Eher\OAuth\Token $requestToken
     * @return string
     */
    public function getAuthorizeUrl(\Eher\OAuth\Token $requestToken){
        return sprintf(self::AUTHORIZE_URL, $this->host, urlencode($requestToken->key));
    }


    /**
     * @param \Eher\OAuth\Token $requestToken
     * @param string            $verifier
     *
     * @throws \Exception
     * @return \Eher\OAuth\Token
     */
    public function getAccessToken(\Eher\OAuth\Token $requestToken, $verifier){
        $this->logger->info("Obtaining Access Token", array("host"=>$this->host, "verifier"=>$verifier));
        // create the URL for the Access Token Endpoint
        $url = sprintf(self::ACCESS_TOKEN_URL, $this->host);
        // create an OAuth Request- configure with local parameters
        $oAuthRequest = OAuthRequest::from_consumer_and_token($this->consumer, $requestToken, 'GET', $url);
        $oAuthRequest->set_parameter('oauth_verifier', $verifier);
        $oAuthRequest->sign_request($this->signatureMethod, $this->consumer, $requestToken);
        // Perform request & Retrieve result
        $headers = array($oAuthRequest->to_header(), 'Accept: application/x-www-form-urlencoded');
        $resultString = $this->performRequest($url, 'GET', $headers);
        // parse the result string (should be www-form-urlencoded
        parse_str($resultString, $result);
        // detect problems
        if (isset($result['oauth_problem'])){
            $this->logger->error("Failed to obtain Access Token", array("host"=>$this->host, "verifier"=>$verifier, "problem"=> $result['oauth_problem']));
            throw new \Exception("Failed to retrieve Access Token because: {$result['oauth_problem']}");
        }
        if (!isset($result['oauth_token']) || !isset($result['oauth_token_secret'])){
            $this->logger->error("Failed to obtain Access Token", array("host"=>$this->host, "verifier"=>$verifier));
            throw new \Exception("Failed to retrieve Access Token.");
        }
        // set the access token for later use
        $this->accessToken = new OAuthToken($result['oauth_token'], $result['oauth_token_secret']);
        // return the token
        return $this->accessToken;
    }


    /**
     * @todo Check Status Codes / Response body on error f complete error reporting
     * @param string $url
     * @param string $method
     * @param array  $headers
     * @param string $content
     *
     * @return string
     * @throws \Exception
     */
    private function performRequest($url, $method='GET', $headers=array(), $content=''){
         $context = array(
            'http' => array(
                'content' => $content,
                'header' => implode("\r\n", $headers) . "\r\n",
                'method' => $method,
                'timeout' => 10.0,
                'ignore_errors'=>true
            )
        );
        $response = file_get_contents($url, false, stream_context_create($context));

        if ($response === false){
            $this->logger->error("Request Failed", array('url'=>$url, 'method'=>$method, 'headers'=>$headers, 'content'=>$content));
            throw new \Exception("Error performing request {$url}");
        }
        return $response;
    }
    /**
     * Sets a logger instance on the object
     *
     * @param \Psr\Log\LoggerInterface $logger
     *
     * @return null
     */
    public function setLogger(\Psr\Log\LoggerInterface $logger)
    {
        $this->logger = $logger;
    }
}

