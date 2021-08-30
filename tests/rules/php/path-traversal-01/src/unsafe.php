<?php
$filename = $_GET['path'];
$content = file_get_contents($filename);

$filename2 = $_GET['path'];
$fullpath2 = 'assets/' . $filename2;
$content2 = file_get_contents($fullpath2);

$filename3 = $_GET['path'];
$content3 = file_get_contents('assets/' . $filename3);


readfile($_POST['filename']);
readfile("assets/" . $_POST['filename']);
?>
