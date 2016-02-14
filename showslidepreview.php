<?php

require_once('../../config.php');
require_once('lib.php');

$id  = optional_param('id', 0, PARAM_INT);

$file = mediaboard_getfileid($id);

header('Content-Type: image/jpeg');

$img = imagecreatefromjpeg($file->fullpatch);

imagejpeg($img);
imagedestroy($img);

