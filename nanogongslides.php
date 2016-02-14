<?php  // $Id: view.php,v 1.4 2006/08/28 16:41:20 mark-nielsen Exp $


    require_once("../../config.php");

    $userid                       = optional_param('userid', 0, PARAM_INT);
    $courseid                     = optional_param('courseid', 0, PARAM_INT);
    $filename                     = optional_param('filename', NULL, PARAM_CLEAN);
    $userfile                     = optional_param('voicefile','',PARAM_FILE);
    
    $dir = "{$CFG->dataroot}/presentation/{$courseid}/temp/mp3";

    mkdir("{$CFG->dataroot}/presentation/{$courseid}", 0777);
    mkdir("{$CFG->dataroot}/presentation/{$courseid}/temp", 0777);
    mkdir("{$CFG->dataroot}/presentation/{$courseid}/temp/mp3", 0777);
    
    if ($_FILES['voicefile1']['tmp_name'])  move_uploaded_file($_FILES['voicefile1']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile2']['tmp_name'])  move_uploaded_file($_FILES['voicefile2']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile3']['tmp_name'])  move_uploaded_file($_FILES['voicefile3']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile4']['tmp_name'])  move_uploaded_file($_FILES['voicefile4']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile5']['tmp_name'])  move_uploaded_file($_FILES['voicefile5']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile6']['tmp_name'])  move_uploaded_file($_FILES['voicefile6']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile7']['tmp_name'])  move_uploaded_file($_FILES['voicefile7']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile8']['tmp_name'])  move_uploaded_file($_FILES['voicefile8']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile9']['tmp_name'])  move_uploaded_file($_FILES['voicefile9']['tmp_name'], $dir.'/'.$filename.'.wav');
    if ($_FILES['voicefile10']['tmp_name']) move_uploaded_file($_FILES['voicefile10']['tmp_name'], $dir.'/'.$filename.'.wav');

?>ok