<?php 

include_once "../../config.php"; 
include_once "lib.php"; 

$id           = optional_param('id', 0, PARAM_INT); 

?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Slideshow</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<script type="application/x-javascript" src="js/jquery.min.js"></script>
<script type="text/javascript" language="javascript" src="js/niftyplayer.js"></script>
</head>

<body><?php

$item = $DB->get_record("mediaboard_items", array("id"=>$id));

$slide = array();

for($i=1;$i<=10;$i++){
  $name_image = 'image'.$i;
  $name_audio = 'audio'.$i;
  $name_duration = 'duration'.$i;
  
  if (!empty($item->{$name_image})) {
    $slide[$i]['leng']     = $item->{$name_duration};
    
    if ($file = mediaboard_getfileid($item->{$name_audio}))
      $slide[$i]['voice']    = new moodle_url("/pluginfile.php/{$file->contextid}/mod_mediaboard/0/{$file->id}/");
      
    if ($file = mediaboard_getfileid($item->{$name_image})) 
      $slide[$i]['url']      = new moodle_url("/mod/mediaboard/showslidepreview.php", array("id"=>$item->{$name_image}));
    
    $lastkey = $i;
  }
}

?>
<script type="application/x-javascript">
$(document).ready(function(){
  var slideid     = 1;
  var reslideid   = 1;
  var pause       = 0;
  var playmark    = 0;
  window.pause    = pause;
  window.playmark = playmark;
  $('#nav-play').click(function() {
    //console.log(window.playmark +"/" + window.pause + "/" + window.reslideid);
    if (window.playmark == 1 && window.pause == 0) {
      window.pause = 1;
      document.getElementById("audio-"+window.reslideid).pause(); 
      $('#nav-play-btn').attr("src", "img/html5-play.png");
    } else if (window.playmark == 1 && window.pause == 1) {
      window.pause = 0;
      document.getElementById("audio-"+window.reslideid).play(); 
      $('#nav-play-btn').attr("src", "img/html5-pause.png");
    } else {
      showslide(slideid);
    }
  });
  
  $('#nav-rtl').click(function() {
    //console.log(window.reslideid);
    document.getElementById("audio-"+window.reslideid).pause();
    showslide(window.reslideid - 1);
  });
  
  $('#nav-ltr').click(function() {
    //console.log(window.reslideid);
    document.getElementById("audio-"+window.reslideid).pause();
    showslide(window.reslideid + 1);
  });
  
function showslide(slideid) {
  var imagesarray=new Array(); 
<?php 
while(list($key,$value)=each($slide)) {
  echo 'imagesarray['.$key.'] = "'.$value['url'].'";
';
}
reset($slide); ?>
  if (slideid != <?php echo $lastkey + 1; ?>) {
    if (slideid == 1) $('#nav-rtl-btn').attr("src", "img/html5-empty.png"); else $('#nav-rtl-btn').attr("src", "img/html5-rtl.png");
    if (slideid == <?php echo $lastkey; ?>) $('#nav-ltr-btn').attr("src", "img/html5-empty.png"); else $('#nav-ltr-btn').attr("src", "img/html5-ltr.png");
    $('#slidenumber').html(slideid);
  
    $('#imagecanvas').attr("src", imagesarray[slideid]);
    var audio = document.getElementById("audio-"+slideid);
    audio.load();
    audio.play(); 
    window.playmark = 1;
    window.reslideid = slideid;
    $('#nav-play-btn').attr("src", "img/html5-pause.png");
    audio.addEventListener("ended", function() { 
      showslide(slideid + 1);
    }, true);
  } else {
    window.playmark = 0;
    slideid = 1;
    $('#nav-play-btn').attr("src", "img/html5-play.png");
  }
}

  $('.image-slide').click(function() {
    showslide(window.reslideid);
  });
  
  
<?php 
while(list($key,$value)=each($slide)) {
?>
    document.getElementById("audio-<?php echo $key; ?>").addEventListener("loadstart", function() { 
      $('#audio-status').html('<img src="img/html5-loader.gif" />');
    }, true);
    document.getElementById("audio-<?php echo $key; ?>").addEventListener("loadeddata", function() { 
      $('#audio-status').html('');
    }, true);
    document.getElementById("audio-<?php echo $key; ?>").addEventListener("playing", function() { 
      $('#audio-status').html('<img src="img/html5-playing.png" />');
    }, true);
    document.getElementById("audio-<?php echo $key; ?>").addEventListener("ended", function() { 
      $('#audio-status').html('');
    }, true);
<?php
}
reset($slide); ?>
});

(function($) {
  var cache = [];
  $.preLoadImages = function() {
    var args_len = arguments.length;
    for (var i = args_len; i--;) {
      var cacheImage = document.createElement('img');
      cacheImage.src = arguments[i];
      cache.push(cacheImage);
    }
  }
})(jQuery)

jQuery.preLoadImages(<?php 
$urltext = "";
while(list($key,$value)=each($slide)) {
  $urltext .= '"'.$value['url'].'",';
}
$urltext = substr($urltext, 0, -1);
echo $urltext;
reset($slide); ?>, "img/html5-play.png", "img/html5-pause.png", "img/html5-empty.png", "img/html5-rtl.png", "img/html5-ltr.png", "img/html5-playing.png", "img/html5-loader.gif");
</script>

</head>
<body>
<div id="content" style="height:375px;">
<img src="<?php echo $slide[1]['url']; ?>" id="imagecanvas" class="image-slide"/>
</div>
<div style="width:490px;height:40px;background:#eee;padding:4px;border:1px solid #bbb;">
<div style="padding:0 180px;">
<div style="float:left;"><a href="javascript:void(0)" id="nav-rtl" /><img src="img/html5-empty.png" width="36px" height="36px" id="nav-rtl-btn" style="padding:0;border:0"/></a></div>
<div style="float:left;"><a href="javascript:void(0)" id="nav-play" /><img src="img/html5-play.png" width="36px" height="36px" id="nav-play-btn" style="padding:0;border:0"/></a></div>
<div style="float:left;"><a href="javascript:void(0)" id="nav-ltr" /><img src="img/html5-empty.png" width="36px" height="36px" id="nav-ltr-btn" style="padding:0;border:0"/></a></div>
</div>
<div style="position:absolute;left:420px;color:#666;font-size:12px;">Slide: <span id="slidenumber">1</span> of <?php echo $lastkey; ?></div>

<div id="audio-status" style="position:absolute;left:20px;color:#666;font-size:12px;">Loading</div>

</div>

<?php

while(list($key,$value)=each($slide)) {
  if (!@$value['duration'])
    if (!strstr($_SERVER['HTTP_USER_AGENT'], "Firefox"))
      echo '<div><audio src="'.$value['voice'].'" id="audio-'.$key.'" autobuffer="autobuffer" preload="auto"></audio></div>';
    else
      echo '<div><audio src="'.str_replace(".mp3", ".ogg", $value['voice']).'" id="audio-'.$key.'" autobuffer="autobuffer" preload="auto"></audio></div>';
}

?>

</body>
</html>

<?php

/*
function isiphone(){
  if (strstr($_SERVER['HTTP_USER_AGENT'], "iPhone") || strstr($_SERVER['HTTP_USER_AGENT'], "iPad")) 
    return true;
  else
    return false;
}
*/

?>