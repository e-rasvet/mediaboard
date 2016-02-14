<?php

require_once '../../config.php';
require_once 'lib.php';


$data                      = optional_param('data', 0, PARAM_TEXT); 
$value                     = optional_param('value', 0, PARAM_INT); 

$fileid = $data;

if (!empty($data) && !empty($value)) {
  $typesql = 'rating';
  
  if (!$mediaboardid = $DB->get_record("mediaboard_ratings", array("fileid" => $fileid, "userid" => $USER->id))) {
    $add                = new stdClass;
    $add->fileid        = $fileid;
    $add->userid        = $USER->id;
    $add->$typesql      = $value;
    $add->time          = time();
    
    $DB->insert_record("mediaboard_ratings", $add);
  } else {
    $DB->set_field("mediaboard_ratings", $typesql, $value, array("fileid" => $fileid, "userid" => $USER->id));
  }
  
  echo $value;
  
  if ($typesql == 'rating'){
      $mediaboardid = $DB->get_record("mediaboard_ratings", array("fileid" => $fileid, "userid" => $USER->id));
      $mediaboardfiles = $DB->get_record("mediaboard_files", array("id" => $mediaboardid->fileid));
      $cm = get_coursemodule_from_id('mediaboard', $mediaboardfiles->instance);
      $context = get_context_instance(CONTEXT_MODULE, $cm->id);
      
      $mediaboard = $DB->get_record("mediaboard", array("id"=>$cm->instance));
      
      //-----Set grade----//
      
      if (has_capability('mod/mediaboard:teacher', $context)) {
          $catdata  = $DB->get_record("grade_items", array("courseid" => $cm->course, "iteminstance"=> $mediaboard->id, "itemmodule" => 'mediaboard'));
          $gradesdata               = new object;
          $gradesdata->itemid       = $catdata->id;
          $gradesdata->userid       = $mediaboardfiles->userid;
          $gradesdata->rawgrade     = 0;
          $gradesdata->finalgrade   = 0;
          $gradesdata->rawgrademax  = $catdata->grademax;
          $gradesdata->usermodified = $mediaboardfiles->userid;
          $gradesdata->timecreated  = time();
          $gradesdata->time         = time();
                
          if (!$grid = $DB->get_record("grade_grades", array("itemid" => $gradesdata->itemid, "userid" => $gradesdata->userid))) {
              $grid = $DB->insert_record("grade_grades", $gradesdata);
          } else {
              $gradesdata->id = $grid->id;
              $DB->update_record("grade_grades", $gradesdata);
          }
          
          //Count all grades
          
          $filesincourse = $DB->get_records("mediaboard_files", array("instance" => $mediaboardfiles->instance, "userid" => $mediaboardfiles->userid), 'id', 'id');
          
          $filessql = '';
          
          foreach($filesincourse as $filesincourse_){
            $filessql .= $filesincourse_->id.",";
          }
          
          $filessql = substr($filessql, 0, -1);
          
          $allvoites = $DB->get_records_sql("SELECT `id`, `rating`, `userid` FROM {mediaboard_ratings} WHERE `fileid` IN ({$filessql})");
          
          $rate = 0;
          $c = 0;
          foreach ($allvoites as $allvoite) {
              if (has_capability('mod/mediaboard:teacher', $context, $allvoite->userid) && !empty($allvoite->rating)) {
                $rate += $allvoite->rating;
                $c++;
              }
          }

          if ($c > 0) {
            $rate = round ($rate/$c,1);
          }
          
          $gradesdata->rawgrade   = $rate;
          $gradesdata->finalgrade = $rate;

          if(empty($gradesdata->id)) 
            $gradesdata->id = $grid;
          
          $DB->update_record("grade_grades", $gradesdata);
      }
      
      //------------------//
  }
  
  die();
  
}

    if (!$mediaboardid = $DB->get_record("mediaboard_ratings", array("fileid" => $fileid, "userid" => $USER->id))) {
        
        $data                = new stdClass;
        $data->fileid        = $fileid;
        $data->userid        = $USER->id;
        if (!empty($rating)) $data->rating        = $rating;
        if (!empty($ratingRhythm)) $data->ratingrhythm = $ratingRhythm;
        if (!empty($ratingclear)) $data->ratingclear = $ratingclear;
        if (!empty($ratingintonation)) $data->ratingintonation = $ratingintonation;
        if (!empty($ratingspeed)) $data->ratingspeed = $ratingspeed;
        if (!empty($ratingreproduction)) $data->ratingreproduction = $ratingreproduction;
        $data->time  = time();
            
        $DB->insert_record("mediaboard_ratings", $data);
            
        $allvoites = $DB->get_records("mediaboard_ratings", array("fileid" => $fileid));
            
        $rate = 0;
        $c    = 0;

        foreach ($allvoites as $allvoite) {
          if ($allvoite->rating > 0) {
            $rate += $allvoite->rating;
            $c++;
          }
        }
        $rate = round ($rate/$c,1);
            
            
        if (!empty($ratingRhythm)) $rate = $ratingRhythm;
        if (!empty($ratingclear)) $rate = $ratingclear;
        if (!empty($ratingintonation)) $rate = $ratingintonation;
        if (!empty($ratingspeed)) $rate = $ratingspeed;
        if (!empty($ratingreproduction)) $rate = $ratingreproduction;
            
        echo $rate;
        die();
    } else { 
        if (!empty($rating)) $DB->set_field("mediaboard_ratings", "rating", $rating, array("id" => $mediaboardid->id));
        if (!empty($ratingRhythm)) $DB->set_field("mediaboard_ratings", "ratingrhythm", $ratingRhythm, array("id" => $mediaboardid->id));
        if (!empty($ratingclear)) $DB->set_field("mediaboard_ratings", "ratingclear", $ratingclear, array("id" => $mediaboardid->id));
        if (!empty($ratingintonation)) $DB->set_field("mediaboard_ratings", "ratingintonation", $ratingintonation, array("id" => $mediaboardid->id));
        if (!empty($ratingspeed)) $DB->set_field("mediaboard_ratings", "ratingspeed", $ratingspeed, array("id" => $mediaboardid->id));
        if (!empty($ratingreproduction)) $DB->set_field("mediaboard_ratings", "ratingreproduction", $ratingreproduction, array("id" => $mediaboardid->id));
            
            
        $allvoites = $DB->get_records("mediaboard_ratings", array("fileid" => $fileid));
            
        $rate = 0;
        $c = 0;

        foreach ($allvoites as $allvoite) {
          if ($allvoite->rating > 0) {
            $rate += $allvoite->rating;
            $c++;
          }
        }
        
        $rate = round ($rate/$c,1);
            

        if (!empty($ratingRhythm)) $rate = $ratingRhythm;
        if (!empty($ratingclear)) $rate = $ratingclear;
        if (!empty($ratingintonation)) $rate = $ratingintonation;
        if (!empty($ratingspeed)) $rate = $ratingspeed;
        if (!empty($ratingreproduction)) $rate = $ratingreproduction;
            
        echo $rate;
        die();
    }