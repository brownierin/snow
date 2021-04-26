<?php
header("Access-Control-Allow-Origin: *");

header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);

header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");

$origin = $_SERVER['HTTP_ORIGIN'];
header("Access-Control-Allow-Origin: " . $origin);
?>
