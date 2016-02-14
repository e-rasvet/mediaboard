<?php

require_once("../../config.php");
require_once("lib.php");
require_once($CFG->libdir.'/plagiarismlib.php');

$id   = optional_param('id', 0, PARAM_INT);          // Course module ID
$a    = optional_param('a', 0, PARAM_INT);           // mediaboard ID
$mode = optional_param('mode', 'all', PARAM_ALPHA);  // What mode are we in?
$download = optional_param('download' , 'none', PARAM_ALPHA); //ZIP download asked for?

$url = new moodle_url('/mod/mediaboard/submissions.php');
if ($id) {
    if (! $cm = get_coursemodule_from_id('mediaboard', $id)) {
        print_error('invalidcoursemodule');
    }

    if (! $mediaboard = $DB->get_record("mediaboard", array("id"=>$cm->instance))) {
        print_error('invalidid', 'mediaboard');
    }

    if (! $course = $DB->get_record("course", array("id"=>$mediaboard->course))) {
        print_error('coursemisconf', 'mediaboard');
    }
    $url->param('id', $id);
} else {
    if (!$mediaboard = $DB->get_record("mediaboard", array("id"=>$a))) {
        print_error('invalidcoursemodule');
    }
    if (! $course = $DB->get_record("course", array("id"=>$mediaboard->course))) {
        print_error('coursemisconf', 'mediaboard');
    }
    if (! $cm = get_coursemodule_from_instance("mediaboard", $mediaboard->id, $course->id)) {
        print_error('invalidcoursemodule');
    }
    $url->param('a', $a);
}

if ($mode !== 'all') {
    $url->param('mode', $mode);
}
$PAGE->set_url($url);
require_login($course->id, false, $cm);

/*
* If is student
*/

if (!has_capability('mod/mediaboard:grade', get_context_instance(CONTEXT_MODULE, $cm->id))) {
  $url = new moodle_url('/mod/mediaboard/viewrubric.php', array("id"=>$id));
  header('Location: '.$url);
  die();
}



$PAGE->requires->js('/mod/mediaboard/mediaboard.js');

/// Load up the required mediaboard code
require($CFG->dirroot.'/mod/mediaboard/type/'.$mediaboard->mediaboardtype.'/mediaboard.class.php');
$mediaboardclass = 'mediaboard_'.$mediaboard->mediaboardtype;
$mediaboardinstance = new $mediaboardclass($cm->id, $mediaboard, $cm, $course);

if($download == "zip") {
    $mediaboardinstance->download_submissions();
} else {
    $mediaboardinstance->submissions($mode);   // Display or process the submissions
}