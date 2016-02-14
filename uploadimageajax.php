<?php

require_once('../../config.php');
require_once("SimpleImage.php");

$unical    = optional_param('unical', 0, PARAM_INT);
$name      = optional_param('name', NULL, PARAM_TEXT);

foreach ($_FILES as $keytmpname => $valuetmpname) {
    $file = $CFG->dataroot."/" . $keytmpname . ".jpg";
    if (move_uploaded_file($valuetmpname['tmp_name'], $file)) {
        //-------Resize images----------//--500x280
        @$image=imagecreatefromjpeg($file);
        $w=getimagesize($file);
                    
        $width = 500;
        $height = 370;
                    
        if ($w[0] < $w[1]) {
          $imagef = new SimpleImage();
          $imagef->load($file);
          $imagef->resizeToHeight($height);
          $imagef->save($file);
          
          $w=getimagesize($file);
          if($w[0] > $width) {
            $imagef->resizeToWidth($width);
            $imagef->save($file);
          }
        } else if ($w[0] >= $w[1]) {
          $imagef = new SimpleImage();
          $imagef->load($file);
          $imagef->resizeToWidth($width);
          $imagef->save($file);
          
          $w=getimagesize($file);
          if($w[1] > $height) {
            $imagef->resizeToHeight($height);
            $imagef->save($file);
          }
        }
        
        $fs = get_file_storage();
        
        $context = get_context_instance(CONTEXT_USER, $USER->id);
        
        $file_record = new stdClass;
        $file_record->component = 'user';
        $file_record->contextid = $context->id;
        $file_record->userid    = $USER->id;
        $file_record->filearea  = 'public';
        $file_record->filepath  = "/";
        $file_record->itemid    = $unical;
        $file_record->license   = $CFG->sitedefaultlicense;
        $file_record->author    = fullname($USER);
        $file_record->source    = '';
        $file_record->filename  = $name.".jpg";
        $itemid = $fs->create_file_from_pathname($file_record, $file);
        
        unlink($file);
        
        echo $itemid->get_id();
    }
}
