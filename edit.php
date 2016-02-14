<?php  // $Id: edit.php,v 1.4 2010/07/09 16:41:20 Igor Nikulin Exp $

    require_once("../../config.php");
    require_once("lib.php");
    require_once($CFG->dirroot.'/course/moodleform_mod.php');
    require_once($CFG->libdir.'/tablelib.php');
    require_once($CFG->libdir.'/uploadlib.php');
    require_once($CFG->libdir.'/gradelib.php');
    require_once("getid3/getid3.php");
    require_once("SimpleImage.php");

    $id           = optional_param('id', 0, PARAM_INT); 
    $a            = optional_param('a', 'edit', PARAM_TEXT); 
    $name         = optional_param('name', NULL, PARAM_CLEAN); 
    $summary      = optional_param('summary', NULL, PARAM_CLEAN);  
    $slides       = optional_param('slides', NULL, PARAM_CLEAN); 
    $slideimages  = optional_param_array('slideimages', NULL, PARAM_CLEAN);
    $usevoice     = optional_param_array('usevoice', NULL, PARAM_CLEAN);
    $idrec        = optional_param('idrec', NULL, PARAM_CLEAN);
    $mobileslide  = optional_param('mobileslide', NULL, PARAM_CLEAN);
    $submitfile   = optional_param('submitfile', 0, PARAM_INT); 
    $filename     = optional_param('filename', NULL, PARAM_TEXT);  
    $unicalsjpg   = optional_param_array('unicalsjpg', NULL, PARAM_INT);
    $unicalsmp3   = optional_param_array('unicalsmp3', NULL, PARAM_INT);
    $itemyoutube  = optional_param('itemyoutube', NULL, PARAM_CLEAN); 
    
    //print_r ($_POST);
    //die();

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
    
    
    //print_r ($_REQUEST);
    //die();

    require_login($course, true, $cm);

    $contextmodule = get_context_instance(CONTEXT_MODULE, $cm->id);

    add_to_log($course->id, "mediaboard", "edit", "edit.php?id=$cm->id", "$mediaboard->id");
    
    $fs = get_file_storage();
    
    if(@$_FILES['i_image']){
      $c = 0;
      foreach($_FILES['i_image']['tmp_name'] as $k => $v){
        
///Delete old records
        //$fs->delete_area_files($contextmodule->id, 'mod_mediaboard', 'private', $k);
          
        $file_record = new stdClass;
        $file_record->component = 'mod_mediaboard';
        $file_record->contextid = $contextmodule->id;
        $file_record->userid    = $USER->id;
        $file_record->filearea  = 'private';
        $file_record->filepath  = "/";
        $file_record->itemid    = (int)$k;
        $file_record->license   = $CFG->sitedefaultlicense;
        $file_record->author    = fullname($USER);
        $file_record->source    = '';
        $file_record->filename  = "slide_image_{$c}.jpg";
        
        $file = $CFG->dataroot."/tmp.jpg";
        
        move_uploaded_file($v, $file);
        
        //-------Resize images----------//--500x280
        @$image=imagecreatefromjpeg($file);
        $w=getimagesize($file);
                    
        $width = 500;
        $height = 370;
                    
        if ($w[0] < $w[1]) {
          $imagef = new SimpleImage();
          $imagef->load($file);
          $imagef->resizeToHeight($height);
          $imagef->save($file);
          
          $w=getimagesize($file);
          if($w[0] > $width) {
            $imagef->resizeToWidth($width);
            $imagef->save($file);
          }
        } else if ($w[0] >= $w[1]) {
          $imagef = new SimpleImage();
          $imagef->load($file);
          $imagef->resizeToWidth($width);
          $imagef->save($file);
          
          $w=getimagesize($file);
          if($w[1] > $height) {
            $imagef->resizeToHeight($height);
            $imagef->save($file);
          }
        }

        $itemid = $fs->create_file_from_pathname($file_record, $file);
        
        unlink($file);
        $c++;
      }
    }
    
    if(@$_FILES['i_audio']){
      $c = 0;
      foreach($_FILES['i_audio']['tmp_name'] as $k => $v){
///Delete old records
        //$fs->delete_area_files($contextmodule->id, 'mod_mediaboard', 'private', $k);
          
        $file_record = new stdClass;
        $file_record->component = 'mod_mediaboard';
        $file_record->contextid = $contextmodule->id;
        $file_record->userid    = $USER->id;
        $file_record->filearea  = 'private';
        $file_record->filepath  = "/";
        $file_record->itemid    = (int)$k;
        $file_record->license   = $CFG->sitedefaultlicense;
        $file_record->author    = fullname($USER);
        $file_record->source    = '';
        $file_record->filename  = "slide_audio_{$c}.mov";
        
        move_uploaded_file($v, $CFG->dataroot."/tmp.mov");
        
        $itemid = $fs->create_file_from_pathname($file_record, $CFG->dataroot."/tmp.mov");
        
        unlink($CFG->dataroot."/tmp.mov");

        //if (!empty($itemid->get_id())) {
            $add         = new stdClass;
            $add->itemid = $itemid->get_id();
            $add->type   = 'audio/mp3';
            $add->status = 'open';
            $add->name   = md5($CFG->wwwroot.'_'.time().'_'.$c);
            $add->time   = time();
            
            $DB->insert_record("mediaboard_process", $add);
            
        //}
        $c++;
      }
    }
    

///Get unical id for video records
    $unicalid = substr(time(), 5).rand(0,9).rand(0,9);

///Uploading MOV video from device
    if (!empty($_FILES['mov_video']['tmp_name'])){
        $ext = @strtolower(end(explode(".", $_FILES['mov_video']['name'])));
            
        $file_record = new stdClass;
        $file_record->component = 'mod_mediaboard';
        $file_record->contextid = $contextmodule->id;
        $file_record->userid    = $USER->id;
        $file_record->filearea  = 'private';
        $file_record->filepath  = "/";
        $file_record->itemid    = $unicalid;
        $file_record->license   = $CFG->sitedefaultlicense;
        $file_record->author    = fullname($USER);
        $file_record->source    = '';
        $file_record->filename  = $filename.".".$ext;
        $itemid = $fs->create_file_from_pathname($file_record, $_FILES['mov_video']['tmp_name']);
        
        $submitfile = $itemid->get_id();
    }


///Uploading mobile audio
    if (!empty($_FILES['mov_audio']['tmp_name'])){
        $ext = strtolower(end(explode(".", $_FILES['mov_audio']['name'])));
            
        $file_record = new stdClass;
        $file_record->component = 'mod_mediaboard';
        $file_record->contextid = $contextmodule->id;
        $file_record->userid    = $USER->id;
        $file_record->filearea  = 'private';
        $file_record->filepath  = "/";
        $file_record->itemid    = $unicalid;
        $file_record->license   = $CFG->sitedefaultlicense;
        $file_record->author    = fullname($USER);
        $file_record->source    = '';
        $file_record->filename  = $filename.".".$ext;
        $itemid = $fs->create_file_from_pathname($file_record, $_FILES['mov_audio']['tmp_name']);
        
        $submitfile = $itemid->get_id();
        
///Quick mime type fixer
        if ($ext == "3gpp") {
          $add = new stdClass;
          $add->id = $submitfile;
          $add->mimetype = 'audio/3gpp';
          
          $DB->update_record("files", $add);
          //$DB->execute("UPDATE {files} SET `mimetype`='audio/3gpp' WHERE `id` ={$submitfile}");
        }

        if ($ext == "mov") {
          $add = new stdClass;
          $add->id = $submitfile;
          $add->mimetype = 'audio/mp3';
          $add->filename = '.mp3';
          
          $DB->update_record("files", $add);
          //$DB->execute("UPDATE {files} SET `mimetype`='audio/mp3' AND `filename`='.mp3' WHERE `id` ={$submitfile}");
        }
    }

    
    //---------Edit record-----------//
    if ($name && $idrec) {
        $DB->set_field("mediaboard_files", "text", $summary, array("id" => $idrec));
        $DB->set_field("mediaboard_files", "name", $name, array("id" => $idrec));
        
        redirect($CFG->wwwroot.'/mod/mediaboard/view.php?id='.$id, "Done");
    }

    //---------Add record-----------//
    if ($name && empty($idrec)) {
        $data = new stdClass;
        $data->name                  = $name;
        $data->text                  = $summary;
        $data->userid                = $USER->id;
        $data->instance              = $id;
        $data->timemodified          = time();
        
        if (!empty($itemyoutube))
            if (preg_match('%(?:youtube(?:-nocookie)?\.com/(?:[^/]+/.+/|(?:v|e(?:mbed)?)/|.*[?&]v=)|youtu\.be/)([^"&?/ ]{11})%i', $itemyoutube, $match)) 
                $data->itemyoutube = $match[1];
        
        if(!empty($submitfile)) {
          if ($file = mediaboard_getfileid($submitfile)){
            $data->itemoldid = $file->id;
///Update submited file params
            $DB->execute("UPDATE {files} 
    SET `contextid`={$contextmodule->id}, 
    `component`='mod_mediaboard', 
    `filearea`='private', 
    `itemid`={$unicalid}
    WHERE  `component` LIKE  'user'
    AND  `filearea` LIKE  'draft'
    AND  `itemid` ={$submitfile}");
          } else if ($file = mediaboard_getfile($submitfile)){
            $data->itemoldid = $file->id;
///Update submited file params
            $DB->execute("UPDATE {files} 
    SET `contextid`={$contextmodule->id}, 
    `component`='mod_mediaboard', 
    `filearea`='private', 
    `itemid`={$unicalid}
    WHERE  `component` LIKE  'user'
    AND  `filearea` LIKE  'draft'
    AND  `itemid` ={$submitfile}");
          }
          
          if (!empty($data->itemoldid)) {
            $add         = new stdClass;
            $add->itemid = $file->id;
            $add->type   = $file->mimetype;
            $add->status = 'open';
            $add->name   = md5($CFG->wwwroot.'_'.time());
            $add->time   = time();
            
            $DB->insert_record("mediaboard_process", $add);
          }
        }
        
        $idrec = $DB->insert_record('mediaboard_files', $data);
        
        $add             = new stdClass;
        $add->fileid     = $idrec;
        $add->userid     = $USER->id; 
        
        if ($mediaboard->type == 'photo')
          $add->type = $mediaboard->type;
        else
          list($add->type) = explode("/",$file->mimetype); //$mediaboard->type
        
        if (!empty($data->itemoldid))
          $add->videoid   = $data->itemoldid;
        
        if ($slides) {
            foreach($unicalsjpg as $k => $v) {
              $name = 'image'.($k + 1);
              $nameimg = 'img'.($k + 1);
              if ($mediaboard->presetimages == 1)
                $add->{$name} = $mediaboard->{$nameimg};
              else if ($file = mediaboard_getfile($v))
                $add->{$name} = $file->id;
            }
            
            $getID3 = new getID3;
            $getID3->setOption(array('encoding' => 'UTF-8'));
            
            foreach($unicalsmp3 as $k => $v) {
              $name = 'audio'.($k + 1);
              $nameduration = 'duration'.($k + 1);
              if ($file = mediaboard_getfile($v)) {
                $add->{$name} = $file->id;
                
                if($usevoice[$v]) {
                  $ThisFileInfo = $getID3->analyze($file->fullpatch);
                  $add->{$nameduration} = @round((float)$ThisFileInfo['playtime_seconds'] * 1000);
                } else {
                  $add->{$nameduration} = 4000;
                }
              }
            }
        }
        
        $add->time      = time();
        
        $DB->insert_record('mediaboard_items', $add);
        
        redirect($CFG->wwwroot.'/mod/mediaboard/view.php?id='.$id, "Done");
    }
    //------------------------------//

    

/// Print the page header

    $PAGE->set_url('/mod/mediaboard/edit.php', array('id' => $id));
    
    $PAGE->requires->js('/mod/mediaboard/js/jquery.min.js', true);
    $PAGE->requires->js('/mod/mediaboard/js/swfobject.js', true);
    $PAGE->requires->js('/mod/mediaboard/js/ajaxupload.js', true);
    
    $title = $course->shortname . ': ' . format_string($mediaboard->name);
    $PAGE->set_title($title);
    $PAGE->set_heading($course->fullname);
    
    echo $OUTPUT->header();

/// Print the main part of the page


    include('tabs.php');
    
    class mod_mediaboard_add_form extends moodleform {
      function definition() {
        global $COURSE, $CFG, $quizs, $USER, $id, $DB, $mediaboard;
        
        $slides   = optional_param('slides', NULL, PARAM_CLEAN);
        
        $cm = get_coursemodule_from_id('mediaboard', $id);
        
        $mform    =& $this->_form;
        
        $mform->disable_form_change_checker();
        
        $mform->updateAttributes(array('enctype' => 'multipart/form-data'));
        
//-------------------------------------------------------------------------------
        $mform->addElement('header', 'general', get_string('general', 'form'));

        $mform->addElement('text', 'name', get_string('mediaboard_name2', 'mediaboard'), array('size'=>'64'));
        $mform->setType('name', PARAM_TEXT);
        $mform->addRule('name', null, 'required', null, 'client');

        $mform->addElement('htmleditor', 'summary', get_string('mediaboard_descr2', 'mediaboard'));
        
        $unicalidjpg = "1".substr(time(), 5).rand(0,9).rand(0,9);
        $unicalidmp3 = "2".substr(time(), 5).rand(0,9).rand(0,9);
        
        if ($mediaboard->type == 'photo') {
          if (!$slides) {
            $mform->addElement('header', 'mediaboard', 'MediaBoard');
              
            if (mediaboard_get_browser() == "mobileios") {
              $version = preg_replace("/(.*) OS ([0-9]*)_(.*)/","$2", $_SERVER['HTTP_USER_AGENT']);
              if ($version >= 6) {
                $countofslides[0] = "Select";
            
                for ($i=1; $i<= 10; $i++) {
                    $countofslides[$i] = $i;
                }
                
                $slideslist = "";
                for($i=0;$i<=10;$i++){
                  if ($mediaboard->slides == $i)
                    $slideslist .= '<option value="'.$i.'" selected>'.$i.'</option>';
                  else
                    $slideslist .= '<option value="'.$i.'">'.$i.'</option>';
                }
                
                $mform->addElement('html', '<div id="recorsfields">');
                $mform->addElement('html', '<div class="fitem"><div class="fitemtitle"><label for="id_category">'.get_string('mediaboard_selectslides', 'mediaboard').'</label></div><div class="felement fselect"><select name="category" id="id_category">
        '.$slideslist.'
    </select></div></div>');
                $mform->addElement('html', '</div>');
                
                $mform->addElement('html', '<script language="JavaScript">
                $("select").bind("change keyup", function() {
                  $.post("recordsforms.php", { id: "'.$id.'", slides: $(this).val(), userid: "'.$USER->id.'", unicalidjpg: "'.$unicalidjpg.'", unicalidmp3: "'.$unicalidmp3.'" }, function(data){$("#recorsfields").html(data);});
                });</script>');
                
                //$mform->addElement('hidden', 'mobileslide', $fmstime);
                
                for($i=0;$i<=9;$i++){
                  $mform->addelEment('hidden', 'unicalsjpg['.$i.']', $unicalidjpg.$i);
                }
                
                for($i=0;$i<=9;$i++){
                  $mform->addelEment('hidden', 'unicalsmp3['.$i.']', $unicalidmp3.$i);
                }
              } else {
                $ftime = time();
                
                $mediadata = '<h3 style="padding: 0 20px;"><a href="mediaboard://?link='.$CFG->wwwroot.'&id='.$id.'&uid='.$USER->id.'&cid='.$COURSE->id.'&time='.$ftime.'&type=mediaboard" onclick="document.getElementById(\'mform1\').submit();">Add slides</a></h3>';
                
                $mform->addElement('static', 'description', '', $mediadata);
                $mform->addElement('hidden', 'mobileslide', $ftime);
              }
            } else {
              $countofslides[0] = "Select";
          
              for ($i=1; $i<= 10; $i++) {
                  $countofslides[$i] = $i;
              }

              $mform->addElement('html', '<div id="recorsfields">');
              $mform->addElement('html', '<script language="JavaScript">
              $(document).ready(function() {
                $("select").bind("change keyup", function() {
                  $.post("recordsforms.php", { id: "'.$id.'", slides: $(this).val(), userid: "'.$USER->id.'", unicalidjpg: "'.$unicalidjpg.'", unicalidmp3: "'.$unicalidmp3.'" }, function(data){$("#recorsfields").html(data);activateajaximagesuploading();});
                });
              });
  function activateajaximagesuploading() {');
  
              
              for($i=1;$i<=10;$i++) {
                $unicalsjpg[] = $unicalidjpg.($i-1);
                $unicalsmp3[] = $unicalidmp3.($i-1);
                $filename = str_replace(" ", "_", $USER->username).'_'.date("Ymd_Hi", time()).'_'.$i;
                $mform->addElement('html', '
      new AjaxUpload(\'attachment_upload_'.$i.'\', {
        action: \''.$CFG->wwwroot.'/mod/mediaboard/uploadimageajax.php\',
        data: {
          \'unical\' : '.$unicalsjpg[($i-1)].',
          \'name\' : \''.$filename.'\'
        },
        name: \''.$filename.'\',
        autoSubmit: true,
        responseType: false,
        onSubmit: function(file, extension) {
          jQuery(\'#slide_preview_'.$i.'\').html(\'<img src="'.$CFG->wwwroot.'/mod/mediaboard/img/ajax-loader.gif" alt="loadeing"/>\');
        },
        onComplete: function(file, response) {
          var randomnumber=Math.floor(Math.random()*1100);
          jQuery(\'#slide_preview_'.$i.'\').html(\'<img src="'.$CFG->wwwroot.'/mod/mediaboard/showslidepreview.php?id=\'+response+\'&random=\' +randomnumber+ \'" alt=" " width="150"/>\');
        }
      });');
              }
      
              $mform->addElement('html', '};
              </script>');
              
              $slideslist = "";
              for($i=0;$i<=10;$i++){
                if ($mediaboard->slides == $i)
                  $slideslist .= '<option value="'.$i.'" selected>'.$i.'</option>';
                else
                  $slideslist .= '<option value="'.$i.'">'.$i.'</option>';
              }
              
              $mform->addElement('html', '<div class="fitem"><div class="fitemtitle"><label for="id_category">'.get_string('mediaboard_selectslides', 'mediaboard').'</label></div><div class="felement fselect"><select name="category" id="id_category">
      '.$slideslist.'
  </select></div></div>');
              $mform->addElement('html', '</div>');
              
              foreach($unicalsjpg as $k => $v){
                $mform->addelEment('hidden', 'unicalsjpg['.$k.']', $v);
              }
              
              foreach($unicalsmp3 as $k => $v){
                $mform->addelEment('hidden', 'unicalsmp3['.$k.']', $v);
              }
            }
          } else {
              $mform->addElement('hidden', 'slides');
          }
          
          if ($mediaboard->presetimages) {
            $mform->addElement('html', '<script language="JavaScript">
                $.post("recordsforms.php", { id: "'.$id.'", cid: '.$COURSE->id.', slides: '.$mediaboard->slides.', userid: "'.$USER->id.'", unicalidjpg: "'.$unicalidjpg.'", unicalidmp3: "'.$unicalidmp3.'" }, function(data){$("#recorsfields").html(data);activateajaximagesuploading();});
              </script>');
          }
          
        } else {
        
                $filename = str_replace(" ", "_", $USER->username).'_'.date("Ymd_Hi", time());
                $mform->addElement('header', 'videoupload', get_string('videoupload', 'mediaboard')); 

                //-------------- Record ----------------//
                $mediadatavideo = "";
                
                if (mediaboard_is_ios()) {
                  $mediadatavideo .= html_writer::empty_tag("input", array("type" => "file", "name" => "mov_video", "accept"=>"video/*", "capture"=>"camcorder"));
                } else if (mediaboard_get_browser() == 'android'){
                  $mediadatavideo .= html_writer::empty_tag("input", array("type" => "file", "name" => "mov_video", "accept"=>"video/*", "capture"=>"camcorder"));
                } 
                //else {
                  $filepickeroptions = array();
                  //$filepickeroptions['filetypes'] = array('.mp3','.mov','.mp4','.m4a');
                  $filepickeroptions['maxbytes']  = get_max_upload_file_size($CFG->maxbytes);
                  $mform->addElement('filepicker', 'submitfile', get_string('uploadmp4', 'mediaboard'), null, $filepickeroptions);
                //}
                
                if (!mediaboard_is_ios() && mediaboard_get_browser() != 'android') { //Only for PC
                  $mform->addelEment('hidden', 'filename', $filename);
                  $mform->addelEment('hidden', 'iphonelink', '');
                  
                  
                  $mform->addelEment('hidden', 'unicalsmp3[0]', "");
                  
                  $filename = str_replace(" ", "_", $USER->username).'_'.date("Ymd_Hi", time()).'_0';
                  $mform->addElement('html', '
                  <script>
        new AjaxUpload(\'attachment_upload_0\', {
          action: \''.$CFG->wwwroot.'/mod/mediaboard/uploadimageajax.php\',
          data: {
            \'unical\' : '."1".substr(time(), 5).rand(0,9).rand(0,9).',
            \'name\' : \''.$filename.'\'
          },
          name: \''.$filename.'\',
          autoSubmit: true,
          responseType: false,
          onSubmit: function(file, extension) {
            jQuery(\'#slide_preview_0\').html(\'<img src="'.$CFG->wwwroot.'/mod/mediaboard/img/ajax-loader.gif" alt="loadeing"/>\');
          },
          onComplete: function(file, response) {
            var randomnumber=Math.floor(Math.random()*1100);
            jQuery(\'#slide_preview_0\').html(\'<img src="'.$CFG->wwwroot.'/mod/mediaboard/showslidepreview.php?id=\'+response+\'&random=\' +randomnumber+ \'" alt=" " width="150"/>\');
          }
        });

        function callbackjs(e){
          /*
          * Speech to text box stop
          */
          obj = JSON.parse(e.data);
          $("#id_submitfile").val(obj.id);
        }
        </script>');
        
                  $o = "";
                  $o .= html_writer::script('var flashvars={};flashvars.gain=35;flashvars.rate=44;flashvars.call="callbackjs";flashvars.name = "'.$filename.'";flashvars.p = "'.urlencode(json_encode(array("id"=>$id, "userid"=>$USER->id, "i"=>0))).'";flashvars.url = "'.urlencode(new moodle_url("/mod/mediaboard/uploadmp3.php")).'";swfobject.embedSWF("'.(new moodle_url("/mod/mediaboard/js/recorder.swf")).'", "mp3_flash_recorder_0", "220", "200", "9.0.0", "expressInstall.swf", flashvars);');
        //$o .= '<div id="mp3_flash_recorder"></div><div id="mp3_flash_records" style="margin:20px 0;"></div>';

                  $o .= html_writer::tag("div", "", array("id"=>"mp3_flash_recorder_0", "style"=>"float:left;margin-left:200px;"));
                  //$o .= html_writer::end_tag("div");
                  
                  $mform->addElement('header', 'mp3upload', get_string('recordaudio', 'mediaboard')); 
                  
                  $mform->addElement('html', "<div style='margin-left:250px'>".$o."</div>");
                  
                  
                  $youtubeurl = "";
                  /*if (!empty($fileid) && empty($act)) {
                    $data = $DB->get_record("videoboard_files", array("id" => $fileid, "userid" => $USER->id));
                    $mform->addElement('editor', 'summary', '')->setValue( array('text' => $data->summary) );
                    $youtubeurl = $data->itemyoutube;
                  }*/
                
                } //Only for PC
                
                if (!empty($mediadatavideo)) {
                  //$mform->addElement('header', 'videoupload', get_string('videoupload', 'mediaboard')); 
                  $mform->addElement('static', 'description', '', $mediadatavideo);
                }
                
                
                /*
                * Adding audio recorder
                */
                
                if (mediaboard_is_ios() || mediaboard_get_browser() == 'android') {
                  $mform->addElement('header', 'mp3upload', get_string('recordaudio', 'mediaboard'));
                  $mediadataaudio = "";
                  $mediadataaudio .= html_writer::empty_tag("input", array("type" => "file", "name" => "mov_audio", "accept"=>"audio/*", "capture"=>"camcorder"));
                  $mform->addElement('static', 'description', '', $mediadataaudio);
                }
                
                
                
                $mform->addElement('header', 'youtubevideo_header', get_string('youtubevideo', 'mediaboard')); 
                $mform->addElement('textarea', 'itemyoutube', '', 'wrap="virtual" rows="5" cols="100"')->setValue($youtubeurl);
                   
        }
        
        $this->add_action_buttons();
      }
    }


    class mod_mediaboard_edit_form extends moodleform {
      function definition() {
        global $COURSE, $CFG, $quizs, $USER, $idrec, $DB;
        
        $slides   = optional_param('slides', NULL, PARAM_CLEAN);
        $fmstime  = optional_param('fmstime', time(), PARAM_INT); 

        $mform    =& $this->_form;
        
//-------------------------------------------------------------------------------
        $mform->addElement('header', 'general', get_string('general', 'form'));

        $mform->addElement('text', 'name', get_string('mediaboard_name', 'mediaboard'), array('size'=>'64'));
        $mform->setType('name', PARAM_TEXT);
        $mform->addRule('name', null, 'required', null, 'client');

        $mform->addElement('htmleditor', 'summary', get_string('mediaboard_introduction', 'mediaboard'));
        
        //$mform->addElement('file', 'attachment', get_string('attachment', 'forum'));
        $mform->addElement('html', '<div id="fitem_id_attachment" class="fitem fitem_ffile"><div class="fitemtitle"><label for="id_attachment">Attachment (Max size: 1MB) </label></div><div class="felement ffile"><input name="attachment" type="file" id="id_attachment" /></div></div>');
        
        $data = $DB->get_record("mediaboard_files", array("id" => $idrec));
        
        $mform->setDefault('name', $data->name);
        $mform->setDefault('summary', $data->text);
        
        $this->add_action_buttons();
      }
    }
    
    
    if ($idrec) {
        echo html_writer::tag('div', $mediaboard->intro, array('class'=>'box generalbox', 'style' => 'background-color:#cbecb0'));
    
        $mform = new mod_mediaboard_edit_form('edit.php?id='.$id.'&idrec='.$idrec);
        
        $mform->display();
    } else {
        echo html_writer::tag('div', $mediaboard->intro, array('class'=>'box generalbox', 'style' => 'background-color:#cbecb0'));
        
        $mform = new mod_mediaboard_add_form('edit.php?id='.$id);
        
        $mform->display();
    }
    
/// Finish the page
    echo $OUTPUT->footer();

