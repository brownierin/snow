<?php
$data = "test";
$result = openssl_encrypt($data, "aes-128-gcm", $key);
?>