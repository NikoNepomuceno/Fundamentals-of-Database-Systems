<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Database connection settings
$servername = "localhost";
$username = "root";  // Your MySQL username
$password = "";      // Your MySQL password
$dbname = "user_db"; // Database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form data is sent
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Retrieve and sanitize form data
    $role = $_POST['role'];
    $email = htmlspecialchars($_POST['email']);
    $password = $_POST['password'];

    // Query to fetch user based on email and role
    $stmt = $conn->prepare("SELECT password FROM users WHERE email = ? AND role = ?");
    if ($stmt === false) {
        die("Prepare failed: (" . $conn->errno . ") " . $conn->error);
    }
    $stmt->bind_param("ss", $email, $role);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();
        
        // Simulate decryption for demonstration purposes
        $decrypted_password = base64_decode($hashed_password);

        // Check if the provided password matches the stored password
        if ($decrypted_password === $password) {
            // Redirect based on role
            if ($role === 'admin') {
                header('Location: admin_page.php');
                exit();
            } elseif ($role === 'student') {
                header('Location: student_page.php');
                exit();
            }
        } else {
            echo 'Incorrect password.';
        }
    } else {
        echo 'No user found with the given email and role.';
    }

    $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Processing Login</title>
</head>
<body>
    <p>Redirecting...</p>
</body>
</html>

