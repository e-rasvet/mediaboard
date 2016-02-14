<?php // $Id: index.php,v 1.5 2010/07/09 16:41:20 Igor Nikulin Exp $

    require_once("../../config.php");
    require_once("lib.php");

    $id = required_param('id', PARAM_INT); 

    if (! $course = $DB->get_record("course", array("id" => $id))) {
        error("Course ID is incorrect");
    }

    require_login($course->id);

    add_to_log($course->id, "mediaboard", "view all", "index.php?id=$course->id", "");


/// Get all required strings

    $PAGE->set_url('/mod/mediaboard/edit.php', array('id' => $id));
    
    $title = $course->shortname . ': MediaBoards';
    $PAGE->set_title($title);
    $PAGE->set_heading($course->fullname);
    
    echo $OUTPUT->header();
    
/// Get all the appropriate data

    if (! $mediaboards = get_all_instances_in_course("mediaboard", $course)) {
        notice("There are no mediaboards", "../../course/view.php?id=$course->id");
        die;
    }

/// Print the list of instances (your module will probably extend this)

    $timenow  = time();
    $strname  = get_string("name");
    $strweek  = get_string("week");
    $strtopic = get_string("topic");
    
    $table    = new html_table();

    if ($course->format == "weeks") {
        $table->head  = array ($strweek, $strname);
        $table->align = array ("center", "left");
    } else if ($course->format == "topics") {
        $table->head  = array ($strtopic, $strname);
        $table->align = array ("center", "left", "left", "left");
    } else {
        $table->head  = array ($strname);
        $table->align = array ("left", "left", "left");
    }

    foreach ($mediaboards as $mediaboard) {
        if (!$mediaboard->visible) {
            $link = html_writer::link(new moodle_url("/mod/mediaboard/view.php", array('id'=>$mediaboard->coursemodule)), $mediaboard->name, array('class'=>'dimmed'));
        } else {
            $link = html_writer::link(new moodle_url("/mod/mediaboard/view.php", array('id'=>$mediaboard->coursemodule)), $mediaboard->name);
        }

        if ($course->format == "weeks" or $course->format == "topics") {
            $table->data[] = array ($mediaboard->section, $link);
        } else {
            $table->data[] = array ($link);
        }
    }

    echo html_writer::empty_tag('br');

    if ($table) 
        echo html_writer::table($table);
    

/// Finish the page

    echo $OUTPUT->footer();

