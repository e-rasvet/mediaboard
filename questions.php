<?php  // $Id: view.php,v 1.4 2010/07/09 16:41:20 Igor Nikulin Exp $

    require_once("../../config.php");
    require_once("lib.php");
    require_once ($CFG->dirroot.'/course/moodleform_mod.php');
    
    $id               = optional_param('id', 0, PARAM_INT); // Course Module ID, or
    $a                = optional_param('a', 'questions', PARAM_TEXT);  // mediaboard ID
    $p                = optional_param('p', NULL, PARAM_CLEAN); 

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
    
    if ($_POST['name_1']) {
        $DB->delete_records("mediaboard_questions", array("fileid" => $p));
        foreach ($_POST as $key => $value) {
            if (strstr($key, "name_")) {
                $idq = (int) str_replace("name_", "", $key);
                
                $data                 = new object;
                $data->instance       = $id;
                $data->fileid         = $p;
                $data->name           = optional_param('name_'.$idq, NULL, PARAM_CLEAN);
                $data->userid         = $USER->id;
                $data->timemodified   = time();
                
                if ($idqr = $DB->insert_record("mediaboard_questions", $data)) {
                    $data                 = new object;
                    $data->questionid     = $idqr;
                    $data->name           = optional_param('cha_'.$idq, NULL, PARAM_CLEAN);
                    $data->grade          = optional_param('cka_'.$idq, 0, PARAM_INT);
                    $data->timemodified   = time();
                    if ($data->name) $DB->insert_record("mediaboard_choice", $data);
                    $data                 = new object;
                    $data->questionid     = $idqr;
                    $data->name           = optional_param('chb_'.$idq, NULL, PARAM_CLEAN);
                    $data->grade          = optional_param('ckb_'.$idq, 0, PARAM_INT);
                    $data->timemodified   = time();
                    if ($data->name) $DB->insert_record("mediaboard_choice", $data);
                    $data                 = new object;
                    $data->questionid     = $idqr;
                    $data->name           = optional_param('chc_'.$idq, NULL, PARAM_CLEAN);
                    $data->grade          = optional_param('ckc_'.$idq, 0, PARAM_INT);
                    $data->timemodified   = time();
                    if ($data->name) $DB->insert_record("mediaboard_choice", $data);
                    $data                 = new object;
                    $data->questionid     = $idqr;
                    $data->name           = optional_param('chd_'.$idq, NULL, PARAM_CLEAN);
                    $data->grade          = optional_param('ckd_'.$idq, 0, PARAM_INT);
                    $data->timemodified   = time();
                    if ($data->name) $DB->insert_record("mediaboard_choice", $data);
                    
                    $DB->set_field ("mediaboard_files", "multiplechoicequestions", $idqr, array("id" => $p));
                }
            }
        }
        redirect($CFG->wwwroot.'/mod/mediaboard/view.php?id='.$id, "Done");
    }

/// Print the page header

    $PAGE->set_url('/mod/mediaboard/questions.php', array('id' => $id));
    
    $title = $course->shortname . ': ' . format_string($mediaboard->name);
    $PAGE->set_title($title);
    $PAGE->set_heading($course->fullname);
    
    echo $OUTPUT->header();

/// Print the main part of the page

    include('tabs.php');
    
    echo $OUTPUT->box_start('generalbox');
    
    echo '<script type="text/javascript" src="js/jquery.min.js"></script>';
    
    $data = $DB->get_record("mediaboard_files", array("id" => $p));
    
    echo '<script type="text/javascript" charset="utf-8">

var metaid = 2;

function addFormFieldMeta() {
    var metarowid = window.metaid;
    jQuery("#divTxtMeta").append(\'<div id="row_meta_\'+metarowid+\'" style="clear: both;-moz-border-radius:6px 6px 6px 6px;background-color:#F3F3F3;list-style-type:none;padding:5px 5px 5px 10px;margin:5px"> \
    <table> \
    <tr> \
    <td width="200px" align="right"><strong>Question \'+metarowid+\'</strong></td> \
    <td width="60px" align="right">'.get_string('mediaboard_questionname', 'mediaboard').'</td> \
    <td colspan="3"><input type="text" name="name_\'+metarowid+\'" value="" style="width:400px;" /></td> \
    </tr> \
    <tr> \
    <td></td> \
    <td align="right">A</td> \
    <td><input type="text" name="cha_\'+metarowid+\'" value="" style="width:320px;" /></td> \
    <td width="10px"><input type="checkbox" name="cka_\'+metarowid+\'" value="1"></td> \
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> \
    </tr> \
    <tr> \
    <td></td> \
    <td align="right">B</td> \
    <td><input type="text" name="chb_\'+metarowid+\'" value="" style="width:320px;" /></td> \
    <td width="10px"><input type="checkbox" name="ckb_\'+metarowid+\'" value="1"></td> \
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> \
    </tr> \
    <tr> \
    <td></td> \
    <td align="right">C</td> \
    <td><input type="text" name="chc_\'+metarowid+\'" value="" style="width:320px;" /></td> \
    <td width="10px"><input type="checkbox" name="ckc_\'+metarowid+\'" value="1"></td> \
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> \
    </tr> \
    <tr> \
    <td></td> \
    <td align="right">D</td> \
    <td><input type="text" name="chd_\'+metarowid+\'" value="" style="width:320px;" /></td> \
    <td width="10px"><input type="checkbox" name="ckd_\'+metarowid+\'" value="1"></td> \
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> \
    </tr> \
    </table> \
    </div>\');
    metarowid = (metarowid - 1) + 2;
    window.metaid = metarowid;
}
function removeFormFieldMeta(metarowid) {
    jQuery(metarowid).remove();
}
</script> 

<form method="post" action="questions.php?id='.$id.'&p='.$p.'">
<div id="divTxtMeta">
<div id="row_meta_1" style="clear: both;-moz-border-radius:6px 6px 6px 6px;background-color:#F3F3F3;list-style-type:none;padding:5px 5px 5px 10px;margin:5px">
<table> 
    <tr> 
    <td width="200px" align="right"><strong>Question 1</strong></td> 
    <td width="60px" align="right">'.get_string('mediaboard_questionname', 'mediaboard').'</td> 
    <td colspan="3"><input type="text" name="name_1" value="" style="width:400px;" /></td> 
    </tr> 
    <tr> 
    <td></td> 
    <td align="right">A</td> 
    <td><input type="text" name="cha_1" value="" style="width:320px;" /></td> 
    <td width="10px"><input type="checkbox" name="cka_1" value="1"></td> 
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> 
    </tr> 
    <tr> 
    <td></td> 
    <td align="right">B</td> 
    <td><input type="text" name="chb_1" value="" style="width:320px;" /></td> 
    <td width="10px"><input type="checkbox" name="ckb_1" value="1"></td> 
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> 
    </tr> 
    <tr> 
    <td></td> 
    <td align="right">C</td> 
    <td><input type="text" name="chc_1" value="" style="width:320px;" /></td> 
    <td width="10px"><input type="checkbox" name="ckc_1" value="1"></td> 
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> 
    </tr> 
    <tr> 
    <td></td> 
    <td align="right">D</td> 
    <td><input type="text" name="chd_1" value="" style="width:320px;" /></td> 
    <td width="10px"><input type="checkbox" name="ckd_1" value="1"></td> 
    <td>'.get_string('mediaboard_correct', 'mediaboard').'</td> 
    </tr> 
</table>
</div>
</div>
<div style="margin-left:40px;"><a href="#" onClick="addFormFieldMeta(); return false;">'.get_string('mediaboard_add', 'mediaboard').'</a></div>';
    
    echo '<div style="clear: both;padding-top:10px;text-align:center;">
<p class="submit"><input type="submit" name="submit" value="'.get_string('mediaboard_create', 'mediaboard').'" /></p>
</div>
</form>';
    
    echo $OUTPUT->box_end();

/// Finish the page
    echo $OUTPUT->footer();
    
    
