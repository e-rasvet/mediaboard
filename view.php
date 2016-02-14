<?php  // $Id: view.php,v 1.4 2010/07/09 16:41:20 Igor Nikulin Exp $

    require_once("../../config.php");
    require_once("lib.php");
    require_once ($CFG->dirroot.'/course/moodleform_mod.php');
    
    $id               = optional_param('id', 0, PARAM_INT); // Course Module ID, or
    $a                = optional_param('a', 'list', PARAM_TEXT);  // mediaboard ID
    $groupshow        = optional_param('groupshow', 'group_all', PARAM_TEXT);  // mediaboard ID
    $orderby          = optional_param('orderby', NULL, PARAM_CLEAN); 
    $sort             = optional_param('sort', NULL, PARAM_CLEAN); 
    $page             = optional_param('page', 1, PARAM_INT); 
    $cid              = optional_param('cid', 1, PARAM_INT); 
    $p                = optional_param('p', NULL, PARAM_CLEAN); 
    $delete           = optional_param('delete', NULL, PARAM_CLEAN); 
    $textcomment      = optional_param('textcomment', NULL, PARAM_CLEAN); 
    $searchtext       = optional_param('searchtext', NULL, PARAM_CLEAN); 
    $act              = optional_param('act', NULL, PARAM_TEXT); 

    if ($id) {
        if (! $cm = get_coursemodule_from_id('mediaboard', $id)) {
            error('Course Module ID was incorrect');
        }

        if (! $course = $DB->get_record('course', array('id' => $cm->course))) {
            error('Course is misconfigured');
        }

        if (! $mediaboard = $DB->get_record('mediaboard', array('id' => $cm->instance))) {
            error('Course module is incorrect');
        }
    } else {
        error('You must specify a course_module ID or an instance ID');
    }

    require_login($course, true, $cm);

    $contextmodule = get_context_instance(CONTEXT_MODULE, $cm->id);

    add_to_log($course->id, "mediaboard", "view", "view.php?id=$cm->id", "$mediaboard->id");

    if ($delete) {
        $data = $DB->get_record("mediaboard_files", array("id" => $delete));
        if (has_capability('mod/mediaboard:teacher', $contextmodule) || $USER->id == $data->userid) {
            $DB->delete_records("mediaboard_files", array("id" => $delete));
            $DB->delete_records("mediaboard_items", array("fileid" => $delete));
        }
    }

    if ($textcomment) {
        $data                = new object;
        $data->instance      = $id;
        $data->userid        = $USER->id;
        $data->fileid        = $p;
        $data->text          = $textcomment;
        $data->timemodified  = time();
        
        $DB->insert_record ("mediaboard_comments", $data);
        
        unset($_GET);
        unset($_POST);
    }
    
    
/*
* Likes
*/
    if ($act == "addlike") {
      if (!$DB->get_record("mediaboard_likes", array("fileid" => $p, "userid" => $USER->id))){
        $add = new stdClass;
        $add->instance      = $id;
        $add->fileid        = $p;
        $add->userid        = $USER->id;
        $add->time          = time();
        
        $data = $DB->get_record("mediaboard_files", array("id" => $p));
        
        if ($USER->id != $data->userid)
          $DB->insert_record("mediaboard_likes", $add);
      }
    }


    if ($act == "dellike") 
      $DB->delete_records("mediaboard_likes", array("fileid"=>$p, "userid" => $USER->id));


    if ($act == "delcom") 
      $DB->delete_records("mediaboard_comments", array("id"=>$cid, "userid" => $USER->id));


/// Print the page header
    $PAGE->set_url('/mod/mediaboard/view.php', array('id' => $id));
    
    $PAGE->requires->js('/mod/mediaboard/js/jquery.min.js', true);
    
    $PAGE->requires->js('/mod/mediaboard/js/flowplayer.min.js', true);
    $PAGE->requires->js('/mod/mediaboard/js/swfobject.js', true);


    $PAGE->requires->js('/mod/mediaboard/js/mediaelement-and-player.min.js', true);
    $PAGE->requires->css('/mod/mediaboard/css/mediaelementplayer.css');

    $PAGE->requires->js('/mod/mediaboard/js/video.js', true);
    $PAGE->requires->css('/mod/mediaboard/css/video-js.css');
    
    $title = $course->shortname . ': ' . format_string($mediaboard->name);
    $PAGE->set_title($title);
    $PAGE->set_heading($course->fullname);
    
    echo $OUTPUT->header();
    
    //echo "<script type='text/javascript' src='http://yandex.st/jquery/1.7.1/jquery.min.js'></script>";

/// Print the main part of the page

    include('tabs.php');
    
    echo html_writer::tag('div', $mediaboard->name, array('class'=>'box generalbox', 'style' => 'background-color:#afddfa;padding: 10px 10px 1px 10px;font-size: 20px;margin: 0 0 10px 0;'));
    
    if ($p) {
        echo html_writer::start_tag('div', array('style' => 'width:700px;float:left;'));
    
        echo html_writer::link(new moodle_url('/mod/mediaboard/view.php', array("id" => $id)), get_string("backtomedialist", "mediaboard"), array("style"=>"font-size:20px;margin:15px 0;"));
    
        mediaboard_show_slide($p);
        
        echo html_writer::link(new moodle_url('/mod/mediaboard/view.php', array("id" => $id)), get_string("backtomedialist", "mediaboard"), array("style"=>"font-size:20px;margin:15px 0;"));
        
        echo html_writer::script('
 $(document).ready(function() {
  $(".mediaboard_rate_box").change(function() {
    var value = $(this).val();
    var data  = $(this).attr("data-url");
    
    var e = $(this).parent();
    e.html(\'<img src="img/ajax-loader.gif" />\');
    
    $.get("ajax.php", {id: '.$id.', act: "setrating", data: data, value: value}, function(data) {
      e.html(data); 
    });
  });
 });
    ');
        
        echo '<div id="comments"></div>';
        
        $comments = $DB->get_records("mediaboard_comments", array("fileid" => $p));
        
        if($comments){
          foreach ($comments as $comment) {
            echo $OUTPUT->box_start('generalbox');
            echo html_writer::start_tag('div', array('style' => 'background-color: #dbeef3;padding: 5px;margin: 5px;'));
            echo format_text($comment->text);
            
            $datauser = $DB->get_record("user", array("id" => $comment->userid));
            
            if ($USER->id == $comment->userid)
              $delcom = '<a href="'.$CFG->wwwroot.'/mod/mediaboard/view.php?id='.$id.'&p='.$p.'&act=delcom&cid='.$comment->id.'">['.get_string("deletecommenet", "mediaboard").']</a>';
            else
              $delcom = '';
            
            echo '<div style="text-align:right"><small>'.date("H:i d.m.Y", $comment->timemodified).' <a href="'.$CFG->wwwroot.'/user/view.php?id='.$id.'&course='.$course->id.'">'. fullname($datauser).'('.$datauser->username.')</a> '.$delcom.'</small></div>';
            
            echo html_writer::end_tag('div');
            echo $OUTPUT->box_end();
          }
        }

        if ($mediaboard->allowcomment == "yes") {
            echo $OUTPUT->box_start('generalbox');
            class mediaboard_comment_form extends moodleform {
                function definition() {
                    global $COURSE, $CFG, $cm, $USER, $mediaboard;
                    $mform    =& $this->_form;
                    $mform->addElement('header', 'general', get_string('mediaboard_comment', 'mediaboard'));
                    
                    $mform->addElement('htmleditor', 'textcomment', get_string('mediaboard_text', 'mediaboard'));
                    $mform->setType('textcomment', PARAM_TEXT);
                    $mform->addRule('textcomment', null, 'required', null, 'client');
                    
                    $this->add_action_buttons($cancel = false);
                }
            }
            
            $mform = new mediaboard_comment_form('view.php?id='.$id.'&p='.$p);
            $mform->display(); 
            echo $OUTPUT->box_end();
        }
        
        echo html_writer::end_tag('div');
        
        echo html_writer::start_tag('div', array('style' => 'width:200px;float:left;padding:10px'));
        
        if ($data = $DB->get_records_sql("SELECT * FROM {mediaboard_files} WHERE instance={$id}  ORDER BY timemodified LIMIT 0,15")){
            foreach ($data as $data_) {
              echo html_writer::start_tag('div', array('style' => 'padding:10px'));
              echo mediaboard_show_slide_img($data_->id);
              echo html_writer::end_tag('div');
            }
        }
        
        echo html_writer::end_tag('div');
        
        echo html_writer::tag('div', '', array("style"=>"clear:both"));
        
    } else {
        $from = $page * 30 - 30;
        
        if ($searchtext) {
          if ($groupshow == "group_all") {
            $searchtextsql = " WHERE text LIKE '%{$searchtext}%' ";
          }
          else
          {
            $searchtextsql = " AND text LIKE '%{$searchtext}%' ";
          }
        }
      
        if(!$searchtext){
           $data = $DB->get_records_sql("SELECT * FROM {mediaboard_files} WHERE instance={$id}  ORDER BY timemodified LIMIT {$from}, 30");
        }else  if ($groupshow == "group_all") {
            $data = $DB->get_records_sql("SELECT * FROM {mediaboard_files} {$searchtextsql} ORDER BY timemodified LIMIT {$from}, 30");
        } else if ($groupshow == "group_wg") {
            $data = $DB->get_records_sql("SELECT * FROM {mediaboard_files} WHERE groupid=0 {$searchtextsql} ORDER BY timemodified LIMIT {$from}, 30");
        } else {
            $data = $DB->get_records_sql("SELECT * FROM {mediaboard_files} WHERE groupid={$groupshow} {$searchtextsql} ORDER BY timemodified LIMIT {$from}, 30");
        }
        
        $totalcount = count($data);
        
        echo $OUTPUT->box_start('generalbox');
        
        
        if ($mediaboard->grademethod == "rubrics") {
          echo html_writer::start_tag('div');
          echo html_writer::link(new moodle_url('/mod/mediaboard/submissions.php', array("id" => $id)), get_string("rubrics", "mediaboard"));
          echo html_writer::end_tag('div');
        }
        
        echo '<div style=""><form action="view.php?id='.$id.'&groupshow='.$groupshow.'" method="post"><input style="width: 680px;" type="text" name="searchtext" value="'.$searchtext.'" /> <input type="submit" name="submit" value="'.get_string('mediaboard_search', 'mediaboard').'" /></form></div>';
    
        echo $OUTPUT->box_end();
    
        $pagingbar = new paging_bar($totalcount, $page, 30, "view.php?id={$id}&groupshow={$groupshow}&");
        echo $OUTPUT->render($pagingbar); 
        
        if($data){
          foreach ($data as $data_) {
            mediaboard_show_slide_shot($data_->id);
          }
        }
        
        
        //$pagingbar = new paging_bar($totalcount, $page, 30, "view.php?id={$id}&groupshow={$groupshow}&");
        echo $OUTPUT->render($pagingbar); 
    }


/*
    echo html_writer::script('
$(document).ready(function() {
  $(".mediaboard-youtube-poster").click(function() {
    $("#mediaboard-player-"+$(this).attr("data-url")).show();
    $(this).hide();
  });
  
  $(".mediaelementplayer").mediaelementplayer();
});');
*/
    echo html_writer::script('
$(document).ready(function() {
  $(".mediaboard-youtube-poster").click(function() {
    $("#mediaboard-player-"+$(this).attr("data-url")).html(\'<iframe type="text/html" width="500" height="368" src="https://www.youtube.com/embed/\'+$(this).attr("data-text")+\'" frameborder="0"></iframe>\');
  });
  
  $(".mediaelementplayer").mediaelementplayer();
});');

    echo '<style>.vs-like-dis{opacity:0.4}.vs-like-dis:hover{opacity:1}.vs-like-grade{padding: 6px;border: 1px solid #888889;background-color: #eaf1dd;margin: 6px;}</style>';

    echo $OUTPUT->footer();

