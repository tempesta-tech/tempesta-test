<!DOCTYPE html>
<html>
<head><title>#1394?</title></head>
<body style="background-color:black;">
  <h1>#1394?</h1>
<?php
  $n = (int) ($_GET["n"] ?? 64);
  $max_dim = (int) ($_GET["max"] ?? 2048);
  $dimensions = array_filter(range(128, 2048, 128), function ($dim) use ($max_dim) {
      return $dim <= $max_dim;
  });
  for ($i = 0; $i < $n; $i++) {
    $dim = $dimensions[array_rand($dimensions)];
    $ver = uniqid();
    echo "<img src='images/$dim.jpg?ver=$ver' alt='$dim'>";
  }
?>
</body>
</html>
