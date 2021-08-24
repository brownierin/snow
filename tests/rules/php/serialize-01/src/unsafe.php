<?php
// Case 1
$abc = unserialize($_POST['value']);

// Case 2
$unsafe_tmp = $_COOKIE['session'];
$def = unserialize($unsafe_tmp);

// Case 3
$unsafe_tmp_2 = $_GET['session'];
$unsafe_tmp_3 = base64_decode($unsafe_tmp_2);
$def = unserialize($unsafe_tmp_3);
?>
