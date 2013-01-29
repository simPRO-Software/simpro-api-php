<?php

namespace MyCompany;

use SimPro\Api\Client as SimProClient;
use Eher\OAuth\Consumer as OAuthConsumer;
use \Monolog\Logger;

if (PHP_SAPI != 'cli') die("This example must be run from the command line");

include (__DIR__ . "/../vendor/autoload.php");

define("SERVER", 'YOUR-SIMPRO-SERVER');
define("CONSUMER_KEY", 'YOUR-CONSUMER-KEY');
define("CONSUMER_SECRET", 'YOUR-SECRET');
define("CALLBACK_URL", "oob");

$Logger = new Logger('api-client');
$Logger->pushHandler(new \Monolog\Handler\StreamHandler('php://stderr'), Logger::INFO);

$Client = new SimProClient(SERVER , new OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET));
$Client->setLogger($Logger);

// get a request token

try {
    $requestToken = $Client->getRequestToken(CALLBACK_URL);

    echo 'RequestToken: ' . $requestToken->to_string(),PHP_EOL,PHP_EOL;

    $authorizeUrl = $Client->getAuthorizeUrl($requestToken);

    echo 'AuthorizeUrl: ' . $authorizeUrl, PHP_EOL;

    do {
        echo PHP_EOL, 'Enter Verifier: ';

        $verifier = trim(fgets(STDIN,30));
    } while ($verifier == '');

    // obtain the access token

    $accessToken = $Client->getAccessToken($requestToken, $verifier);

    echo 'Access Token: ' . $accessToken->to_string(),PHP_EOL,PHP_EOL;

    $result = $Client->CompanySearch();

    echo 'Success!', PHP_EOL;

    var_dump($result);
} catch (\Exception $ex){
    echo 'Error:', $ex->getMessage(), PHP_EOL;
}

