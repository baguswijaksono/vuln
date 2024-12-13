<?php
$conn = null;
$servername = "localhost";
$username = "skibidi";
$password = "skibidi";

// Function to connect to the "vuln" database
function connectVuln(): mysqli
{
    global $conn, $servername, $username, $password;
    $dbname = "vuln";
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die("Connection to URLs database failed: " . $conn->connect_error);
    }
    return $conn;
}
