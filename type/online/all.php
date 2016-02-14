<?php

//===================================================
// all.php
//
// Displays a complete list of online mediaboards
// for the course. Rather like what happened in
// the old Journal activity.
// Howard Miller 2008
// See MDL-14045
//===================================================

require_once("../../../../config.php");
require_once("{$CFG->dirroot}/mod/mediaboard/lib.php");
require_once($CFG->libdir.'/gradelib.php');
require_once('mediaboard.class.php');

// get parameter
$id = required_param('id', PARAM_INT);   // course

if (!$course = $DB->get_record('course', array('id'=>$id))) {
    print_error('invalidcourse');
}

$PAGE->set_url('/mod/mediaboard/type/online/all.php', array('id'=>$id));

require_course_login($course);

// check for view capability at course level
$context = get_context_instance(CONTEXT_COURSE,$course->id);
require_capability('mod/mediaboard:view',$context);

// various strings
$str = new stdClass;
$str->mediaboards = get_string("modulenameplural", "mediaboard");
$str->duedate = get_string('duedate','mediaboard');
$str->duedateno = get_string('duedateno','mediaboard');
$str->editmysubmission = get_string('editmysubmission','mediaboard');
$str->emptysubmission = get_string('emptysubmission','mediaboard');
$str->nomediaboards = get_string('nomediaboards','mediaboard');
$str->onlinetext = get_string('typeonline','mediaboard');
$str->submitted = get_string('submitted','mediaboard');

$PAGE->navbar->add($str->mediaboards, new moodle_url('/mod/mediaboard/index.php', array('id'=>$id)));
$PAGE->navbar->add($str->onlinetext);

// get all the mediaboards in the course
$mediaboards = get_all_instances_in_course('mediaboard',$course, $USER->id );

$sections = get_all_sections($course->id);

// array to hold display data
$views = array();

// loop over mediaboards finding online ones
foreach( $mediaboards as $mediaboard ) {
    // only interested in online mediaboards
    if ($mediaboard->mediaboardtype != 'online') {
        continue;
    }

    // check we are allowed to view this
    $context = get_context_instance(CONTEXT_MODULE, $mediaboard->coursemodule);
    if (!has_capability('mod/mediaboard:view',$context)) {
        continue;
    }

    // create instance of mediaboard class to get
    // submitted mediaboards
    $onlineinstance = new mediaboard_online( $mediaboard->coursemodule );
    $submitted = $onlineinstance->submittedlink(true);
    $submission = $onlineinstance->get_submission();

    // submission (if there is one)
    if (empty($submission)) {
        $submissiontext = $str->emptysubmission;
        if (!empty($mediaboard->timedue)) {
            $submissiondate = "{$str->duedate} ".userdate( $mediaboard->timedue );

        } else {
            $submissiondate = $str->duedateno;
        }

    } else {
        $submissiontext = format_text( $submission->data1, $submission->data2 );
        $submissiondate  = "{$str->submitted} ".userdate( $submission->timemodified );
    }

    // edit link
    $editlink = "<a href=\"{$CFG->wwwroot}/mod/mediaboard/view.php?".
        "id={$mediaboard->coursemodule}&amp;edit=1\">{$str->editmysubmission}</a>";

    // format options for description
    $formatoptions = new stdClass;
    $formatoptions->noclean = true;

    // object to hold display data for mediaboard
    $view = new stdClass;

    // start to build view object
    $view->section = get_section_name($course, $sections[$mediaboard->section]);

    $view->name = $mediaboard->name;
    $view->submitted = $submitted;
    $view->description = format_module_intro('mediaboard', $mediaboard, $mediaboard->coursemodule);
    $view->editlink = $editlink;
    $view->submissiontext = $submissiontext;
    $view->submissiondate = $submissiondate;
    $view->cm = $mediaboard->coursemodule;

    $views[] = $view;
}

//===================
// DISPLAY
//===================

$PAGE->set_title($str->mediaboards);
echo $OUTPUT->header();

foreach ($views as $view) {
    echo $OUTPUT->container_start('clearfix generalbox mediaboard');

    // info bit
    echo $OUTPUT->heading("$view->section - $view->name", 3, 'mdl-left');
    if (!empty($view->submitted)) {
        echo '<div class="reportlink">'.$view->submitted.'</div>';
    }

    // description part
    echo '<div class="description">'.$view->description.'</div>';

    //submission part
    echo $OUTPUT->container_start('generalbox submission');
    echo '<div class="submissiondate">'.$view->submissiondate.'</div>';
    echo "<p class='no-overflow'>$view->submissiontext</p>\n";
    echo "<p>$view->editlink</p>\n";
    echo $OUTPUT->container_end();

    // feedback part
    $onlineinstance = new mediaboard_online( $view->cm );
    $onlineinstance->view_feedback();

    echo $OUTPUT->container_end();
}

echo $OUTPUT->footer();