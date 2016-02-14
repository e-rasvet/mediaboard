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
<script type="application/x-javascript" src="js/jquery-2.1.3.min.js"></script>
<!--<script type="text/javascript" language="javascript" src="js/niftyplayer.js"></script>-->
<script type="text/javascript" language="javascript" src="js/jquery.jplayer.min2.js"></script>
</head>

<body><?php

$item = $DB->get_record("mediaboard_items", array("id"=>$id));

$slide = array();
$totallength = 0;

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
    
    $totallength += $slide[$i]['leng'];
  }
}

if ($file = mediaboard_getfileid($item->combinateaudio)) {
  $mp3file  = "http://learn.core.kochi-tech.ac.jp/moodle/mod/mediaboard/getmp3.php?t="; 
  $mp3file .= urlencode(new moodle_url("/pluginfile.php/{$file->contextid}/mod_mediaboard/0/{$file->id}/"));  //new moodle_url("/pluginfile.php/{$file->contextid}/mod_mediaboard/0/{$file->id}/"); //
  }
//echo '<A href="'.$mp3file.'">'.$mp3file.'</a>';

?>
<script type="application/x-javascript">
$(document).ready(function(){
//-----SET MP3---------//
	window.my_jPlayer = $("#jquery_jplayer");

	window.my_jPlayer.jPlayer({
    loadstart: function () {
      $('#audio-status').html('<img src="img/html5-loader.gif" />');
    },
    loadeddata: function () {
      $('#audio-status').html('');
    },
		ready: function () {
			
		},
		timeupdate: function(event) {
      var duration = event.jPlayer.status.currentPercentAbsolute;
			var ctime = parseInt(event.jPlayer.status.currentTime * 1000);
			console.log(ctime+' - '+duration);
			
			/*
			if (duration == 100) {
			  console.log("Force END");
			  window.my_jPlayer.jPlayer("stop");
        showslide(<?php echo $lastkey + 1; ?>);
        $('#audio-status').html('');
			} else {
			*/
			console.log(window.playmark+'-'+window.pause);
        if (window.playmark == 1 && window.pause == 0){
          <?php
          $c = 0;
          $d = 0;
          while(list($key,$value)=each($slide)) {
            $c++;
            
            if ($c > 1) {
              if (empty($tfrom)) $tfrom = 0;
              $tto = $d;
              echo ' if (ctime >= '.$tfrom.' && ctime < '.$tto.') {
                showslide('.($c - 1).');
              } else';
              
              $tfrom = $d;
            }
            $d += $value['leng'];
          }
          reset($slide);
          
          ?> {
            showslide(<?php echo $c; ?>);
          }
        }
      //}
		},
		play: function(event) {
      $('#audio-status').html('<img src="img/html5-playing.png" />');
		},
		pause: function(event) {
			
		},
		ended: function(event) {
		  console.log("END");
		  window.location.reload();
		},
		swfPath: "js",
		cssSelectorAncestor: "#jp_container",
		supplied: "mp3",
		wmode: "window"
	});

	window.my_jPlayer.jPlayer("setMedia", {
		mp3: '<?php echo $mp3file; ?>'
	});
//---------------------//

  window.imagesarray = new Array(); 
  <?php 
  while(list($key,$value)=each($slide)) {
    echo 'window.imagesarray['.$key.'] = "'.$value['url'].'";
  ';
  }
  reset($slide); ?>
  
  window.startheaderarray = new Array(); 
  <?php
  $c = 0;
  $tfrom = 0;
  while(list($key,$value)=each($slide)) {
    $c++;
    if (empty($tfrom)) $tfrom = 0;
    echo 'window.startheaderarray['.$c.'] = '.round(($tfrom / $totallength) * 100).';
  ';
    $tfrom += $value['leng'];
  }
  reset($slide);
  
  ?>

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
      window.my_jPlayer.jPlayer("pause");
      console.log("PAUSED");
      $('#nav-play-btn').attr("src", "img/html5-play.png");
    } else if (window.playmark == 1 && window.pause == 1) {
      window.pause = 0;
      window.my_jPlayer.jPlayer("play");
      $('#nav-play-btn').attr("src", "img/html5-pause.png");
    } else if (window.playmark == 0 && window.pause == 0) {
      window.my_jPlayer.jPlayer("playHead", 0);
      window.my_jPlayer.jPlayer("play");
      window.playmark = 1;
      window.reslideid = 1;
      $('#nav-play-btn').attr("src", "img/html5-pause.png");
      showslide(1);
    }
  });
  
  $('#nav-rtl').click(function() {
    //console.log(window.reslideid);
    var slide = window.reslideid - 1;
    window.my_jPlayer.jPlayer("pause");
    window.pause = 1;
    window.playmark = 1;
    showslide(slide);
    window.my_jPlayer.jPlayer("playHead", window.startheaderarray[slide]);
    console.log(slide + ' : rtl');
  });
  
  $('#nav-ltr').click(function() {
    //console.log(window.reslideid);
    var slide = window.reslideid + 1;
    window.my_jPlayer.jPlayer("pause");
    window.pause = 1;
    window.playmark = 1;
    showslide(slide);
    window.my_jPlayer.jPlayer("playHead", window.startheaderarray[slide]);
    console.log(slide + ' : ltr');
  });
  
function showslide(slideid) {
  console.log(slideid + ' -- Set slide');
  if (!isNaN(slideid)) {
      console.log(slideid + " -- slide");
      if (slideid != <?php echo $lastkey + 1; ?>) {
        if (slideid == 1) $('#nav-rtl-btn').attr("src", "img/html5-empty.png"); else $('#nav-rtl-btn').attr("src", "img/html5-rtl.png");
        if (slideid == <?php echo $lastkey; ?>) $('#nav-ltr-btn').attr("src", "img/html5-empty.png"); else $('#nav-ltr-btn').attr("src", "img/html5-ltr.png");
        $('#slidenumber').html(slideid);
      
        $('#imagecanvas').attr("src", window.imagesarray[slideid]);
        /*
        if (slideid == 1) {
          window.my_jPlayer.jPlayer("play");
          window.playmark = 1;
          window.reslideid = slideid;
          $('#nav-play-btn').attr("src", "img/html5-pause.png");
        }
        */
        window.reslideid = slideid;
      } else {
        console.log("last slide");
        window.playmark = 0;
        slideid = 1;
        showslide(slideid);
        $('#nav-play-btn').attr("src", "img/html5-play.png");
      }
    }

    //$('.image-slide').click(function() {
    //  showslide(window.reslideid);
    //});
  }
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
<div style="float:left;"><a href="#" id="nav-rtl" /><img src="img/html5-empty.png" width="36px" height="36px" id="nav-rtl-btn" style="padding:0;border:0"/></a></div>
<div style="float:left;"><a href="#" id="nav-play" /><img src="img/html5-play.png" width="36px" height="36px" id="nav-play-btn" style="padding:0;border:0"/></a></div>
<div style="float:left;"><a href="#" id="nav-ltr" /><img src="img/html5-empty.png" width="36px" height="36px" id="nav-ltr-btn" style="padding:0;border:0"/></a></div>
</div>
<div style="position:absolute;left:420px;color:#666;font-size:12px;">Slide: <span id="slidenumber">1</span> of <?php echo $lastkey; ?></div>

<div id="audio-status" style="position:absolute;left:20px;color:#666;font-size:12px;">Loading</div>

</div>

<div id="jquery_jplayer"></div>

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