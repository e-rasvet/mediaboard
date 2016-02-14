<?php  // $Id: view.php,v 1.4 2010/07/09 16:41:20 Igor Nikulin Exp $

    require_once("../../config.php");
    require_once("lib.php");
    require_once ($CFG->dirroot.'/course/moodleform_mod.php');
    
    $id               = optional_param('id', 0, PARAM_INT);
    $a                = optional_param('a', 'questions', PARAM_TEXT); 
    $p                = optional_param('p', NULL, PARAM_CLEAN); 
    $submit           = optional_param('submit', NULL, PARAM_CLEAN); 

    if ($id) {
        if (! $cm = $DB->get_record("course_modules", array("id" => $id))) {
            error("Course Module ID was incorrect");
        }
    
        if (! $course = $DB->get_record("course", array("id" => $cm->course))) {
            error("Course is misconfigured");
        }
    
        if (! $mediaboard = $DB->get_record("mediaboard", array("id" => $cm->instance))) {
            error("Course module is incorrect");
        }

    } else {
        if (! $mediaboard = $DB->get_record("mediaboard", array("id" => $a))) {
            error("Course module is incorrect");
        }
        if (! $course = $DB->get_record("course", array("id" => $mediaboard->course))) {
            error("Course is misconfigured");
        }
        if (! $cm = get_coursemodule_from_instance("mediaboard", $mediaboard->id, $course->id)) {
            error("Course Module ID was incorrect");
        }
    }

    require_login($course->id);

    add_to_log($course->id, "mediaboard", "view", "view.php?id=$cm->id", "$mediaboard->id");
    
    if ($submit) {
      foreach ($_POST as $key => $value) {
        if (strstr($key, "ck_")) {
          $idch = str_replace("ck_", "", $key);
          
          if ($dataq = $DB->get_record("mediaboard_choice", array("id" => $idch))) {
            $data                 = new object;
            $data->questionid     = $dataq->questionid;
            $data->userid         = $USER->id;
            $data->answerid       = $idch;
            $data->timemodified   = time();
            
            $DB->insert_record("mediaboard_answer", $data);
          }
        }
      }
    }
    
/// Print the page header

    $PAGE->set_url('/mod/mediaboard/question_test.php', array('id' => $id));
    
    $title = $course->shortname . ': ' . format_string($mediaboard->name);
    $PAGE->set_title($title);
    $PAGE->set_heading($course->fullname);
    
    echo $OUTPUT->header();

    
    $data   = $DB->get_records("mediaboard_questions", array("fileid" => $p));
    
    echo '<form action="question_test.php?id='.$id.'&p='.$p.'" method="post">';
    
    $nosubmit = false;
    
    foreach ($data as $data_) {
        $dataansfers = $DB->get_records_sql("SELECT * FROM {mediaboard_answer} WHERE questionid=? and userid=?", array($data_->id, $USER->id));

        echo '<div id="row_meta_1" style="clear: both;-moz-border-radius:6px 6px 6px 6px;background-color:#F3F3F3;list-style-type:none;padding:5px 5px 5px 10px;margin:5px"><table><tr>
        <td width="50px"></td>
        <td colspan="2" align="center"><strong>'.$data_->name.'</strong></td>
        <td width="100px"></td>
        </tr>';
        $datach = $DB->get_records("mediaboard_choice", array("questionid" => $data_->id));
        foreach ($datach as $datach_) {
            if ($dataansfers) {
                $nosubmit = true;
                $youransfer = "";
                foreach ($dataansfers as $dataansfer) {
                    if ($datach_->id == $dataansfer->answerid) $youransfer = get_string('mediaboard_youransfer', 'mediaboard');
                }
                if ($datach_->grade == "0") $ansferci = get_string('mediaboard_incorrect', 'mediaboard'); else $ansferci = get_string('mediaboard_correct', 'mediaboard');
                
                echo '<tr>
        <td width="50px"></td>';
                if (!empty($youransfer) && $datach_->grade != "0") {
                    echo '<td width="200px" align="right">'.$datach_->name.'</td>
        <td width="200px"><font color="green">'.$youransfer.' '.$ansferci.'</font></td>';
                }
                else
                {
                    echo '<td width="200px" align="right">'.$datach_->name.'</td>
        <td width="200px">'.$youransfer.' '.$ansferci.'</td>';
                }
                echo '<td width="100px"></td>
        </tr>';
            }
            else
            {
                echo '<tr>
        <td width="50px"></td>
        <td width="200px" align="right">'.$datach_->name.'</td>
        <td width="50px"><input type="checkbox" name="ck_'.$datach_->id.'" value="1" /></td>
        <td width="100px"></td>
        </tr>';
            }
        }
        echo '<tr>
        </tr></table></div>';
    }
    
    if (!$nosubmit) echo '<div id="row_meta_1" style="clear: both;-moz-border-radius:6px 6px 6px 6px;background-color:#F3F3F3;list-style-type:none;padding:5px 5px 5px 10px;margin:5px"><table width="450px"><tr>
        <td align="center"><input type="submit" name="submit" value="'.get_string('mediaboard_submit', 'mediaboard').'" /></td></tr></table></div>';
    
    echo '</form>';
    
/// Finish the page
    echo $OUTPUT->footer();
    
    
