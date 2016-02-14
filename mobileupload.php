<?php

    require_once("../../config.php");
    require_once("lib.php");
    require_once("SimpleImage.php");
    require_once("getid3/getid3.php");
    
    $id                     = optional_param('id', 0, PARAM_INT);
    $cid                    = optional_param('cid', 0, PARAM_INT);
    $uid                    = optional_param('uid', 0, PARAM_INT);
    $time                   = optional_param('time', NULL, PARAM_CLEAN);
    $type                   = optional_param('type', NULL, PARAM_CLEAN);
    $slideimages            = optional_param('slideimages', NULL, PARAM_CLEAN);
    $fname                  = optional_param('fname', NULL, PARAM_CLEAN);
    
    $userdata = $DB->get_record("user", array("id"=>$uid));
    $data = $DB->get_record_sql("SELECT * FROM {mediaboard_files} WHERE userid=? AND instance=? ORDER BY id DESC", array($uid, $id));
    $aid = $data->id;
    
    $unicalid = substr(time(), 2).rand(0,9);
    
    $contextmodule = get_context_instance(CONTEXT_MODULE, $data->instance);
    $context = get_context_instance(CONTEXT_USER, $uid);
    
    $fs = get_file_storage();

    list(,$sid) = explode("_", $fname);
    
    if ($type == 'image') {
      $file = $CFG->dataroot."/tmp.jpg";
      if (move_uploaded_file($_FILES['media']['tmp_name'], $file)) {
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

          $file_record = new stdClass;
          $file_record->component = 'mod_mediaboard';
          $file_record->contextid = $contextmodule->id;
          $file_record->userid    = $uid;
          $file_record->filearea  = 'private';
          $file_record->filepath  = "/";
          $file_record->itemid    = $unicalid;
          $file_record->license   = $CFG->sitedefaultlicense;
          $file_record->author    = fullname($userdata);
          $file_record->source    = '';
          $file_record->filename  = "slide_image.jpg";

          $itemid = $fs->create_file_from_pathname($file_record, $file);

          unlink($file);
          
          $DB->set_field("mediaboard_items", "image".$sid, $itemid->get_id(), array("fileid"=>$aid));
      }
    } else if ($type == 'audio') {
        $file = $CFG->dataroot."/tmp.m4a";
        if (move_uploaded_file($_FILES['media']['tmp_name'], $file)) {
          $file_record = new stdClass;
          $file_record->component = 'mod_mediaboard';
          $file_record->contextid = $contextmodule->id;
          $file_record->userid    = $uid;
          $file_record->filearea  = 'private';
          $file_record->filepath  = "/";
          $file_record->itemid    = $unicalid;
          $file_record->license   = $CFG->sitedefaultlicense;
          $file_record->author    = fullname($userdata);
          $file_record->source    = '';
          $file_record->filename  = "slide_audio.m4a";

          $itemid = $fs->create_file_from_pathname($file_record, $file);
          
          $getID3 = new getID3;
          $getID3->setOption(array('encoding' => 'UTF-8'));
          $ThisFileInfo = $getID3->analyze($file);
          
          unlink($CFG->dataroot."/tmp.m4a");
          
          $DB->set_field("mediaboard_items", "audio".$sid, $itemid->get_id(), array("fileid"=>$aid));
          $DB->set_field("mediaboard_items", "duration".$sid, @round((float)$ThisFileInfo['playtime_seconds'] * 1000), array("fileid"=>$aid));
          $DB->set_field("mediaboard_items", "combinateaudio", 0, array("fileid"=>$aid));

          $add         = new stdClass;
          $add->itemid = $itemid->get_id();
          $add->type   = 'audio/mp3';
          $add->status = 'open';
          $add->name   = md5($CFG->wwwroot.'_'.time().'_'.$sid);
          $add->time   = time();
              
          $DB->insert_record("mediaboard_process", $add);
        }
    }
