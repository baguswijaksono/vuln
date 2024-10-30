<?php
function conn()
{
    $servername = "localhost";
    $username = "phpmyadmin";
    $password = "your_password";
    $dbname = "vulnerability_tracker";
    $conn = new mysqli($servername, $username, $password, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    return $conn;
}
