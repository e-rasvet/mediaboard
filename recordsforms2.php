<?php

require_once("../../config.php");

$slides   = optional_param('slides', NULL, PARAM_CLEAN); 
$userid   = optional_param('userid', NULL, PARAM_CLEAN);
$fmstime  = optional_param('fmstime', NULL, PARAM_CLEAN);
$cid      = optional_param('cid', NULL, PARAM_CLEAN);
$update   = optional_param('instance', NULL, PARAM_CLEAN);


$mediadata = "";

if(!empty($update)) {
  $cm = get_coursemodule_from_id('mediaboard', $update);
  $mediaboard = $DB->get_record("mediaboard", array("id"=>$cm->instance));
}

for ($i=1; $i <= $slides; $i++) {
    $mediadata .= '<div><a href="#" id="attachment_upload_'.$fmstime.'_'.$i.'" class="showarrow">Select image (*.jpg) for slide.</a></div>
    <div id="slide_preview_'.$i.'">';
    
    $name = 'img'.$i;
    
    if(!empty($update) && !empty($mediaboard->{$name})) {
      $mediadata .= '<img src="'.$CFG->wwwroot.'/mod/mediaboard/showslidepreview.php?id='.$mediaboard->{$name}.'&amp;random='.rand(999,9999).'" alt=" " width="150">';
    }
    
    $mediadata .= '</div><hr /><br />';
}

echo "<center>".$mediadata."<input type=\"hidden\" value=\"".$slides."\" name=\"slides\" /></center>";

