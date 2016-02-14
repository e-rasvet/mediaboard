<?php

include_once("../../config.php");

if (!empty($_SERVER['QUERY_STRING']))
  $dir = $CFG->dataroot.''.$_SERVER['QUERY_STRING'];
else
  $dir = $CFG->dataroot.''.$_SERVER['PATH_INFO'];


if (strstr($dir, ".jpg")) {
  header('Content-Type: image/jpeg');
  $img=imagecreatefromjpeg($dir);
  imagejpeg($img);
  imagedestroy($img);
} else if (strstr($dir, ".mp3")) {
    header("Content-type: audio/x-mpeg");
   
    if (isset($_SERVER['HTTP_RANGE']))  { 
      mediaboard_rangeDownload($dir); 
    } else {
      header("Content-Length: ".filesize($dir));
      readfile($dir);
    }
} else if (strstr($dir, ".ogg")) {
  header('Content-type: application/ogg');
  header('Content-Length: '.filesize($dir));
  readfile($dir);
}


    function mediaboard_rangeDownload($file) {
      $fp = @fopen($file, 'rb');
     
      $size   = filesize($file); // File size
      $length = $size;           // Content length
      $start  = 0;               // Start byte
      $end    = $size - 1;       // End byte

      header("Accept-Ranges: 0-$length");

      if (isset($_SERVER['HTTP_RANGE'])) {
        $c_start = $start;
        $c_end   = $end;
        list(, $range) = explode('=', $_SERVER['HTTP_RANGE'], 2);
        if (strpos($range, ',') !== false) {
          header('HTTP/1.1 416 Requested Range Not Satisfiable');
          header("Content-Range: bytes $start-$end/$size");

          exit;
        }

        if ($range0 == '-') {
          $c_start = $size - substr($range, 1);
        } else {
          $range  = explode('-', $range);
          $c_start = $range[0];
          $c_end   = (isset($range[1]) && is_numeric($range[1])) ? $range[1] : $size;
        }
        $c_end = ($c_end > $end) ? $end : $c_end;
        if ($c_start > $c_end || $c_start > $size - 1 || $c_end >= $size) {
          header('HTTP/1.1 416 Requested Range Not Satisfiable');
          header("Content-Range: bytes $start-$end/$size");

          exit;
        }
        $start  = $c_start;
        $end    = $c_end;
        $length = $end - $start + 1; 
        fseek($fp, $start);
        header('HTTP/1.1 206 Partial Content');
      }

      header("Content-Range: bytes $start-$end/$size");
      header("Content-Length: $length");
     
      $buffer = 1024 * 8;
      while(!feof($fp) && ($p = ftell($fp)) <= $end) {
        if ($p + $buffer > $end) {
          $buffer = $end - $p + 1;
        }
        set_time_limit(0); 
        echo fread($fp, $buffer);
        flush(); 
      }
     
      fclose($fp);
    }
