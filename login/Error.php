<?php
// Start session if you plan to use session variables
session_start();

include("DB.php");

// Display errors for debugging (remove or disable in production)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Check if form data is sent
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Retrieve and sanitize form data
    $usersId = htmlspecialchars(trim($_POST['email']));
    $password = trim($_POST['password']);

    // Validate and handle missing role
    if (!isset($_POST['role']) || empty($_POST['role'])) {
        $login_error = 'Please select your role (Admin or Student).';
    } else {
        $role = $_POST['role'];

        // Prepare the SQL statement
        $stmt = $conn->prepare("SELECT Pass FROM login INNER JOIN users ON login.usersId = users.usersId WHERE login.usersId = ? AND users.role = ?");
        if ($stmt === false) {
            die("Prepare failed: (" . $conn->errno . ") " . $conn->error);
        }

        // Bind parameters and execute the statement
        $stmt->bind_param("ss", $usersId, $role);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($hashed_password);
            $stmt->fetch();

            // Verify the provided password against the stored hashed password
            if (password_verify($password, $hashed_password)) {
                // Redirect based on role (assuming correct file names)
                if ($role === 'admin') {
                    header('Location: admin_page.php');
                    exit();
                } elseif ($role === 'student') {
                    header('Location: student.php');
                    exit();
                }
            } else {
                $login_error = 'Incorrect password.';
            }
        } else {
            $login_error = 'No user found with the given ID and role.';
        }

        $stmt->close();
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log-in Page</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@100..900&display=swap" rel="stylesheet">
</head>

<body>

    <div class="background-container">
        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>

        <div class="square"></div>
    </div>

    <div class="logo-container">
        <img src="images/CAS-logo.png" alt="">
    </div>

    <div class="box-container">
        <!-- Form to capture selection and credentials -->
        <form action="login.php" method="post">
            <div class="selection">
                <div>
                    <p><input type="radio" name="role" value="admin"> Admin</p>
                    <p><input type="radio" name="role" value="student"> Student</p>
                </div>
            </div>

            <h2><b>Sign in to your Account</b></h2>

            <div class="inputs">
                <p>Email or Student number</p>
                <input type="text" name="email" placeholder="Enter your Email or Student number" required>
            </div>

            <div class="inputs">
                <p>Password</p>
                <input type="password" name="password" placeholder="Enter your Password" required>
            </div>

            <p class="forgot"><a href="#">forgot password?</a></p>

            <button type="submit">Log in</button>
        </form>
    </div>

    <div class="footer">
        <p>©2024 Databoys</p>
    </div>

    <script>
        // JavaScript to randomly position background squares
        const squares = document.querySelectorAll('.square');
        squares.forEach(square => {
            square.style.top = Math.random() * 100 + 'vh';
            square.style.left = Math.random() * 100 + 'vw';
        });

        document.querySelectorAll('.box-container .selection div p').forEach(function (p) {
            p.addEventListener('click', function () {
                document.querySelectorAll('.box-container .selection div p').forEach(function (el) {
                    el.classList.remove('clicked');
                });
                this.classList.add('clicked');
            });
        });
    </script>
</body>

</html>


