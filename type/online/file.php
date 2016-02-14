<?php

require("../../../../config.php");
require("../../lib.php");
require("mediaboard.class.php");

$id     = required_param('id', PARAM_INT);      // Course Module ID
$userid = required_param('userid', PARAM_INT);  // User ID

$PAGE->set_url('/mod/mediaboard/type/online/file.php', array('id'=>$id, 'userid'=>$userid));

if (! $cm = get_coursemodule_from_id('mediaboard', $id)) {
    print_error('invalidcoursemodule');
}

if (! $mediaboard = $DB->get_record("mediaboard", array("id"=>$cm->instance))) {
    print_error('invalidid', 'mediaboard');
}

if (! $course = $DB->get_record("course", array("id"=>$mediaboard->course))) {
    print_error('coursemisconf', 'mediaboard');
}

if (! $user = $DB->get_record("user", array("id"=>$userid))) {
    print_error('usermisconf', 'mediaboard');
}

require_login($course->id, false, $cm);

$context = get_context_instance(CONTEXT_MODULE, $cm->id);
if (($USER->id != $user->id) && !has_capability('mod/mediaboard:grade', $context)) {
    print_error('cannotviewmediaboard', 'mediaboard');
}

if ($mediaboard->mediaboardtype != 'online') {
    print_error('invalidtype', 'mediaboard');
}

$mediaboardinstance = new mediaboard_online($cm->id, $mediaboard, $cm, $course);


$PAGE->set_pagelayout('popup');
$PAGE->set_title(fullname($user,true).': '.$mediaboard->name);

$PAGE->requires->js('/mod/mediaboard/js/jquery.min.js', true);
    
$PAGE->requires->js('/mod/mediaboard/js/flowplayer.min.js', true);
$PAGE->requires->js('/mod/mediaboard/js/swfobject.js', true);

$PAGE->requires->js('/mod/mediaboard/js/mediaelement-and-player.min.js', true);
$PAGE->requires->css('/mod/mediaboard/css/mediaelementplayer.css');
$PAGE->requires->js('/mod/mediaboard/js/video.js', true);
$PAGE->requires->css('/mod/mediaboard/css/video-js.css');

echo $OUTPUT->header();
echo $OUTPUT->box_start('generalbox boxaligcenter', 'dates');

/*
$lists = $DB->get_records ("mediaboard_files", array("userid" => $user->id), 'time DESC');

foreach ($lists as $list) {
  if ($cml = get_coursemodule_from_id('mediaboard', $list->instance)) {
    if ($cml->course == $cm->course && $cml->instance == $cm->instance) {
      
    }
  }
}
*/

if ($data = $DB->get_records("mediaboard_files", array("instance"=>$cm->id, "userid"=>$user->id))){
  foreach($data as $data_){
    if ($item = $DB->get_record("mediaboard_items", array("fileid"=>$data_->id))) {
        if (mediaboard_isiphone())
          $fmslink2 = new moodle_url("/mod/mediaboard/html5mediaboard_iphone.php", array("id"=>$item->id));
        else
          $fmslink2 = new moodle_url("/mod/mediaboard/html5mediaboard.php", array("id"=>$item->id));
          
        $fmshtml2 = '<iframe src="'.$fmslink2.'" style="border: medium none;" height="433px" scrolling="no" width="508px">
  &lt;p&gt;Your browser does not support iframes.&lt;/p&gt;
           </iframe>';
        
        $height = "200px";
    } else {
        $fmshtml2 = '<div style="margin: 10px;"><h3><a href="view.php?id='.$id.'&p='.$data_->id.'">'.$data_->name.'</a></h3></div>';
        $height = "100px";
        $fmshtml2 .= html_writer::tag('div', mediaboard_player($data_->id));
    }
    
    echo '<div>'.$fmshtml2.'</div>';
  }
}

echo $OUTPUT->box_end();
echo $OUTPUT->close_window_button();
echo $OUTPUT->footer();

