<?php

$whitelist = array("www.example.org", "example.org");
$index = array_serach($_SERVER['HTTP_ORIGIN'], $whitelist);

if ($index !== false) {
    header("Access-Control-Allow-Origin: " . $whitelist[$index]);
}

?>
