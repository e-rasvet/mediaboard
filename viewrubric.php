<?php

require_once("../../config.php");
require_once("lib.php");
require_once($CFG->libdir . '/completionlib.php');
require_once($CFG->libdir . '/plagiarismlib.php');

$id = optional_param('id', 0, PARAM_INT);  // Course Module ID
$a  = optional_param('a', 0, PARAM_INT);   // mediaboard ID

$url = new moodle_url('/mod/mediaboard/view.php');
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
        print_error('invalidid', 'mediaboard');
    }
    if (! $course = $DB->get_record("course", array("id"=>$mediaboard->course))) {
        print_error('coursemisconf', 'mediaboard');
    }
    if (! $cm = get_coursemodule_from_instance("mediaboard", $mediaboard->id, $course->id)) {
        print_error('invalidcoursemodule');
    }
    $url->param('a', $a);
}

$PAGE->set_url($url);
require_login($course, true, $cm);

$PAGE->requires->js('/mod/mediaboard/mediaboard.js');

require ("$CFG->dirroot/mod/mediaboard/type/$mediaboard->mediaboardtype/mediaboard.class.php");
$mediaboardclass = "mediaboard_$mediaboard->mediaboardtype";
$mediaboardinstance = new $mediaboardclass($cm->id, $mediaboard, $cm, $course);

/// Mark as viewed
$completion=new completion_info($course);
$completion->set_module_viewed($cm);

$mediaboardinstance->view();   // Actually display the mediaboard!