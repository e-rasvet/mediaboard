<?php

require_once("../../config.php");
require_once("lib.php");

$id             = optional_param('id', NULL, PARAM_CLEAN); 
$slides         = optional_param('slides', NULL, PARAM_CLEAN); 
$userid         = optional_param('userid', NULL, PARAM_CLEAN);
$municalidjpg   = optional_param('unicalidjpg', NULL, PARAM_CLEAN);
$municalidmp3   = optional_param('unicalidmp3', NULL, PARAM_CLEAN);
$cid            = optional_param('cid', NULL, PARAM_CLEAN);

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

$siteid = explode ("/", $CFG->wwwroot);
$siteid = str_replace (".", "_", $siteid[2]);

$mediadata = "";

$updir    = $CFG->dataroot."/presentation/{$cid}/temp";

if (mediaboard_get_browser() == "mobileios" || mediaboard_get_browser() == 'android') {
  for ($i=1; $i <= $slides; $i++) {
      $imagename   = 'img'.$i;
      $unicalidjpg = $municalidjpg.($i-1);
      $unicalidmp3 = $municalidmp3.($i-1);
      
      $filename = str_replace(" ", "_", $USER->username).'_'.date("Ymd_Hi", time()).'_'.$i;
      
      $o  = "";
      
      $o .= html_writer::tag("div", html_writer::tag("h3", "Slide #".$i));
      
      if ($mediaboard->presetimages == 0) {
        $o .= html_writer::start_tag("div", array("style"=>"float:left;width:250px;margin-left:10px"));
        $o .= "Select image for slide <br />".html_writer::empty_tag("input", array("type" => "file", "name" => "i_image[{$unicalidjpg}]", "accept"=>"image/*", "capture"=>"camera"));
        $o .= html_writer::end_tag("div");
      }

      $o .= html_writer::start_tag("div", array("style"=>"float:left;width:250px;margin-left:10px"));
      //$o .= "Record caption for slide<br />".html_writer::empty_tag("input", array("type" => "file", "name" => "i_audio[{$unicalidmp3}]", "accept"=>"audio/*", "capture"=>"microphone"));
      $o .= "Record caption for slide<br />".html_writer::empty_tag("input", array("type" => "file", "name" => "i_audio[{$unicalidmp3}]", "accept"=>"video/*"));
      $o .= html_writer::end_tag("div");
      
      
      $o .= html_writer::start_tag("div");
      
      $o .= html_writer::start_tag("div", array("style"=>"float:left"));
      
      $o .= html_writer::tag("div", "Use voice record ".html_writer::empty_tag('input', array('type'=>'checkbox', 'name'=>'usevoice['.$unicalidmp3.']', 'value'=> 1, 'checked'=>'checked')));
      
      if ($mediaboard->presetimages == 0)
        $o .= html_writer::tag("div", "", array('id'=>'slide_preview_'.$i));
      else
        $o .= html_writer::tag("div", html_writer::empty_tag('img', array('src'=>new moodle_url('/mod/mediaboard/showslidepreview.php', array("id" => $mediaboard->{$imagename})), "style"=>"width:150px")), array('id'=>'slide_preview_'.$i));
      
      $o .= html_writer::end_tag("div");
      
      $o .= html_writer::end_tag("div");
      
      $o .= html_writer::tag("div", "", array('style'=>'clear:both'));
      
      $o .= html_writer::empty_tag("hr");
      $o .= html_writer::empty_tag("br");
        
      echo $o;
  }
} else {

  echo html_writer::script('
  function callbackjs(e){
    /*
    * Speech to text box stop
    */
    obj = JSON.parse(e.data);
    var oldid = $("input[name=\'unicalsmp3["+(obj.i - 1)+"]\']").val();
    
    $("input[name=\'usevoice["+oldid+"]\']").attr("name", "usevoice["+obj.id+"]");
    
    $("input[name=\'unicalsmp3["+(obj.i - 1)+"]\']").val(obj.id);
  }
  ');

  for ($i=1; $i <= $slides; $i++) {
      $imagename   = 'img'.$i;
      $unicalidjpg = $municalidjpg.($i-1);
      $unicalidmp3 = $municalidmp3.($i-1);
      
      $filename = str_replace(" ", "_", $USER->username).'_'.date("Ymd_Hi", time()).'_'.$i;
      
      $o  = "";
      
      $o .= html_writer::tag("div", html_writer::tag("h3", "Slide #".$i));
      
      if ($mediaboard->presetimages == 0)
        $o .= html_writer::tag("div", html_writer::link("#", 'Select image (*.jpg) for slide.', array('id'=>'attachment_upload_'.$i, 'class'=>'showarrow')));
      
      
      $o .= html_writer::start_tag("div");
      
      $o .= html_writer::tag("div", "Record caption for slide", array("style"=>"float:left"));
      
      
      $o .= html_writer::start_tag("div", array("style"=>"float:left;width:400px;margin-left:10px"));
      //$o .= html_writer::script('var fn = function() {var att = { data:"'.(new moodle_url("/mod/mediaboard/js/recorder.swf")).'", width:"350", height:"200"};var par = { flashvars:"rate=44&gain=50&prefdevice=&loopback=no&echosupression=yes&silencelevel=0&updatecontrol=poodll_recorded_file&callbackjs=poodllcallback&posturl='.(new moodle_url("/mod/mediaboard/uploadmp3.php")).'&p1='.$id.'&p2='.$USER->id.'&p3='.$unicalidmp3.'&p4='.$filename.'&autosubmit=true&debug=false&lzproxied=false" };var id = "mp3_flash_recorder_'.$i.'";var myObject = swfobject.createSWF(att, par, id);};swfobject.addDomLoadEvent(fn);function poodllcallback(args){console.log(args);}');
      
      //261456033

      $o .= html_writer::script('var flashvars={};flashvars.gain=35;flashvars.rate=44;flashvars.call="callbackjs";flashvars.name = "'.$filename.'";flashvars.p = "'.urlencode(json_encode(array("id"=>$id, "userid"=>$USER->id, "i"=>$i))).'";flashvars.url = "'.urlencode(new moodle_url("/mod/mediaboard/uploadmp3.php")).'";swfobject.embedSWF("'.(new moodle_url("/mod/mediaboard/js/recorder.swf")).'", "mp3_flash_recorder_'.$i.'", "220", "200", "9.0.0", "expressInstall.swf", flashvars);');
      //$o .= '<div id="mp3_flash_recorder"></div><div id="mp3_flash_records" style="margin:20px 0;"></div>';

      $o .= html_writer::tag("div", "", array("id"=>"mp3_flash_recorder_".$i, "style"=>"float:left"));
      $o .= html_writer::end_tag("div");
      
      
      $o .= html_writer::start_tag("div", array("style"=>"float:left"));
      
      $o .= html_writer::tag("div", "Use voice record ".html_writer::empty_tag('input', array('type'=>'checkbox', 'name'=>'usevoice['.$unicalidmp3.']', 'value'=> 1, 'checked'=>'checked')));
      
      if ($mediaboard->presetimages == 0)
        $o .= html_writer::tag("div", "", array('id'=>'slide_preview_'.$i));
      else
        $o .= html_writer::tag("div", html_writer::empty_tag('img', array('src'=>new moodle_url('/mod/mediaboard/showslidepreview.php', array("id" => $mediaboard->{$imagename})), "style"=>"width:150px")), array('id'=>'slide_preview_'.$i));
      
      $o .= html_writer::end_tag("div");
      
      $o .= html_writer::end_tag("div");
      
      $o .= html_writer::tag("div", "", array('style'=>'clear:both'));
      
      $o .= html_writer::empty_tag("hr");
      $o .= html_writer::empty_tag("br");
        
      echo $o;
  }
}

echo "<center>".$mediadata."<input type=\"hidden\" value=\"".$slides."\" name=\"slides\" /></center>";

