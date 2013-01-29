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


$Logger = new Logger('api-client');
$Logger->pushHandler(new \Monolog\Handler\StreamHandler('php://stderr'), Logger::INFO);

$Client = new SimProClient(SERVER , new OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET), null);
$Client->setLogger($Logger);

try {
    $result = $Client->CompanySearch();
    echo 'Success!', PHP_EOL;
    var_dump($result);
} catch (\Exception $ex){
    echo 'Error:', $ex->getMessage(), PHP_EOL;
}