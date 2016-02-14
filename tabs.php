<?php  // $Id: mysql.php,v 1.0 2010/07/09 16:41:20 Igor Nikulin

    if (empty($mediaboard)) {
        error('You cannot call this script in that way');
    }
    if (!isset($a)) {
        $a = 'list';
    }
    if (!isset($cm)) {
        $cm = get_coursemodule_from_instance('mediaboard', $mediaboard->id);
    }
    if (!isset($course)) {
        $course = get_record('course', 'id', $mediaboard->course);
    }

    $tabs       = array();
    $row        = array();
    $inactive   = NULL;
    $activetwo  = NULL;
    $secondrow  = array();

    $row[] = new tabobject('list', $CFG->wwwroot . "/mod/mediaboard/view.php?id=" . $id , get_string('mediaboard_listofmediaboards', 'mediaboard'));
    $row[] = new tabobject('edit', $CFG->wwwroot . "/mod/mediaboard/edit.php?id=" . $id , get_string('mediaboard_addnewmediaboard', 'mediaboard'));
    
    $tabs[] = $row;
    
    $groups = groups_get_all_groups($course->id);
    
    if ($groups) {
        $secondrow[] = new tabobject('group_all', $CFG->wwwroot."/mod/mediaboard/view.php?id={$id}&groupshow=group_all", 'List of all Presentations');
        foreach ($groups as $group) {
          $secondrow[] = new tabobject('group_'.$group->id, $CFG->wwwroot."/mod/mediaboard/view.php?id={$id}&groupshow={$group->id}" , "({$group->name}) group");
        }
    }
    
    if ($groups && $a == 'list') {
        $inactive  = array($a);
        $activetwo = array($groupshow);
        
        $tabs = array($row, $secondrow);
    } else {
        $tabs = array($row);
    }
    
	if (isset($p)){
    $inactive   = NULL;
    $activetwo  = NULL;
  }
    
  print_tabs($tabs, $a, $inactive, $activetwo);
