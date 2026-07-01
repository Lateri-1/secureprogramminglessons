<?php
session_start();
include 'includes/db.php';

$error = '';
$success = '';

function validatePassword($password) {
    // Regular expression for strong password
    // min 8 char, 1 small letter, 1 big letter, 1 number, 1 special char
    $pattern = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,}$/';

    return (bool) preg_match($pattern, $password);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $passwordcheck = $_POST['passwordcheck'] ?? '';

    if ($username === '' || $password === '' || $passwordcheck === '') {
        $error = "Vul alle velden in";
    } elseif ($password !== $passwordcheck) {
        $error = "De wachtwoorden komen niet overeen";
    } elseif (!validatePassword($password)) {
        // Deze validatie werd eerder aangemaakt, maar nooit aangeroepen —
        // hierdoor werden zwakke wachtwoorden altijd geaccepteerd.
        $error = "Het wachtwoord voldoet niet aan de gestelde eisen";
    } else {
        $stmt = $pdo->prepare("SELECT * FROM user WHERE username = ?");
        $stmt->execute([$username]);

        if ($stmt->rowCount() > 0) {
            $error = "Deze gebruikersnaam is al in gebruik";
        } else {
            // Pas NU pas de hash aanmaken, nadat alle validatie is geslaagd
            $hash = password_hash($password, PASSWORD_DEFAULT);
 
            $stmt = $pdo->prepare("INSERT INTO user (username, password, balance, isAdmin) VALUES (?, ?, 100, 0)");
            $stmt->execute([$username, $hash]);
 
            $success = "Je account is aangemaakt, je kunt nu inloggen";
            $username = ''; // formulier leegmaken na succes
        }
    }
}
?>
 
<!DOCTYPE html>
<html lang="nl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Omanido - registreren</title>
        <!-- Voeg Tailwind CSS toe via CDN -->
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100">
        <?php include 'includes/header.php'; ?>
    
        <div class="container mx-auto mt-20 p-6 bg-white max-w-sm shadow-md rounded-md">
            <div class="flex justify-center">
                <img src="img/Omanido1.png" alt="Omanido Logo" class="mb-6 w-1/2">
            </div>
            <h2 class="text-lg text-center font-bold mb-6">Registreren bij Omanido</h2>
            <?php if ($error): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                    <strong class="font-bold">Fout!</strong>
                    <span class="block sm:inline"><?= htmlspecialchars($error) ?></span>
                </div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative mb-4" role="alert">
                    <strong class="font-bold">Gelukt!</strong>
                    <span class="block sm:inline"><?= htmlspecialchars($success) ?></span>
                </div>
            <?php endif; ?>
            <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]) ?>" method="post">
                <div class="mb-4">
                    <label for="username" class="block text-sm font-medium text-gray-700">Gebruikersnaam:</label>
                    <input type="text" id="username" name="username"
                        value="<?= htmlspecialchars($username ?? '') ?>"
                        class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div class="mb-6">
                    <label for="password" class="block text-sm font-medium text-gray-700">Wachtwoord:</label>
                    <input type="password" id="password" name="password"
                        class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div class="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <p class="text-gray-700 font-medium mb-2">
                        Het wachtwoord moet minimaal voldoen aan:
                    </p>
    
                    <ul class="list-disc list-inside space-y-1 text-gray-600">
                        <li>Minstens 8 tekens lang</li>
                        <li>Ten minste één kleine letter</li>
                        <li>Ten minste één hoofdletter</li>
                        <li>Ten minste één cijfer</li>
                        <li>Ten minste één speciaal teken (@, $, !, %, *, ?, &, _)</li>
                    </ul>
                </div>
                <div class="mb-6 mt-4">
                    <label for="passwordcheck" class="block text-sm font-medium text-gray-700">Herhaal wachtwoord:</label>
                    <input type="password" id="passwordcheck" name="passwordcheck"
                        class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div class="flex justify-center">
                    <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Registreren</button>
                </div>
            </form>
        </div>
    </body>
</html>