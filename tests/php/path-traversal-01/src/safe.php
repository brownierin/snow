<?php

// Not a dynamic path
$content = file_get_contents("config.xml");

// Safe-handling of path
$path = $_GET['file'];
$fileparts = pathinfo($path);
$content2 = file_get_contents("assets/" . $fileparts['basename']);


?>