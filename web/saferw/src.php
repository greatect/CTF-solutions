 <?php
    $f = $_GET{'f'}; // disallow characters ./-
    $i = $_GET{'i'}; // disallow substring "ph"
    $c = $_GET{'c'}; // require strlen($c > 20) be false

    @system("mkdir " . escapeshellarg($f));
    @chdir($f);
    @file_put_contents("meow", $c);
    @chdir("..");

    if(isset($i) && stripos(file_get_contents($i), '<') === FALSE) {
        echo "<div class='container'>";
        echo "<h2>Here is your file content:</h2>";
        @include($i);
        echo "</div>";
    }
    @system('rm -rf ' . escapeshellarg($f));
?>
