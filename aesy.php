<?php

define("AESY_ENCRYPT", "e");
define("AESY_DECRYPT", "d");

class Aesy
{
    public static function encrypt(string $string, string $key)
    {
        $method = "AES-256-CBC";
        $key = hash('sha256', $key, true);
        $iv = openssl_random_pseudo_bytes(16);
        $ciphertext = openssl_encrypt($string, $method, $key, OPENSSL_RAW_DATA, $iv);
        $hash = hash_hmac('sha256', $ciphertext . $iv, $key, true);

        return base64_encode($iv . $hash . $ciphertext);
    }

    public static function decrypt($encrypted, $key)
    {
        $encrypted = base64_decode($encrypted);
        $method = "AES-256-CBC";
        $iv = substr($encrypted, 0, 16);
        $hash = substr($encrypted, 16, 32);
        $ciphertext = substr($encrypted, 48);
        $key = hash('sha256', $key, true);

        if (!hash_equals(hash_hmac('sha256', $ciphertext . $iv, $key, true), $hash)) return null;

        return openssl_decrypt($ciphertext, $method, $key, OPENSSL_RAW_DATA, $iv);
    }
}

function is_assoc(array $array)
{
    if ([] === $array)
        return false;
    return array_keys($array) !== range(0, count($array) - 1);
}

function parse_args(array $argv, array $expected_keys, bool $debug = false)
{
    $args = [];

    if (empty($expected_keys))
        return null;

    foreach ($expected_keys as $k) {
        $args[$k] = null;
    }

    if (empty($argv)) {
        return null;
    }

    $mode = array_keys($argv) !== range(0, count($argv) - 1) ? "http" : "cli";

    if ($debug) {
        echo "Arguments came in via {$mode}.\n";
        echo "ARGV=";
        var_dump($argv);
        echo "\n";
    }

    // Parse
    switch ($mode) {
        case "cli": {
                if (isset($argv[1])) {
                    foreach ($args as $k => $v) {
                        $i = 0;
                        foreach ($argv as $argument) {
                            if (substr($argument, 0, 2) == "-{$k}") {
                                if (isset($argv[$i + 1])) {
                                    $args[$k] = $argv[$i + 1];
                                    break;
                                } else {
                                    if ($debug)
                                        echo "Failed assignment: \$argv[{$k}] = \$argv[" . ($i + 1) . "]\n";
                                    die("Invalid argument -{$k}.\n");
                                }
                            }
                            $i++;
                        }
                    }
                }
            }
            break;
        case "http": {
                foreach ($args as $k => $v) {
                    if (isset($argv[$k]) && !empty($argv[$k]))
                        $args[$k] = $argv[$k];
                }
            }
            break;
    }


    if ($debug) {
        echo "PARSED=";
        var_dump($args);
        echo "\n";
    }

    foreach ($args as $k => $v) {
        if (empty($v))
            die("Missing argument: -{$k}\n");
    }

    return $args;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if (isset($argv[1])) {
    $arguments = $argv;
} else {
    $arguments = $_GET;
}

$params = parse_args($arguments, ["s", "k", "m"], false);

if (!$params) {
    echo "You can (e)ncrypt or (d)ecrypt a (-s)tring with a (-k)ey.\n";
    exit;
}

$string = $params["s"];
$key = $params["k"];
$mode = $params["m"];

$output = "";

switch ($mode) {
    case "e":
        $output = Aesy::encrypt($string, $key);
        break;
    case "d":
        $output = Aesy::decrypt($string, $key);
        break;
}

echo $output;
