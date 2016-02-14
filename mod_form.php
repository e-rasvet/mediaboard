<?php //$Id


require_once ($CFG->dirroot.'/course/moodleform_mod.php');

class mod_mediaboard_mod_form extends moodleform_mod {

    function definition() {

        global $COURSE, $CFG, $quizs, $USER;
        
        $update = optional_param('update', NULL, PARAM_INT);
        
        $mform    =& $this->_form;
        
        $mform->addElement('select', 'type', get_string('type', "mediaboard"), array('photo'=>'Photo', 'video'=>'Video/Audio'));
        $mform->setDefault('type', 'photo');
        
//-------------------------------------------------------------------------------
        $mform->addElement('header', 'general', get_string('general', 'form'));

        $mform->addElement('text', 'name', get_string('mediaboard_name', 'mediaboard'), array('size'=>'64'));
        $mform->setType('name', PARAM_TEXT);
        $mform->addRule('name', null, 'required', null, 'client');

        $this->add_intro_editor(true, get_string('mediaboard_intro', 'mediaboard'));
//-------------------------------------------------------------------------------

        $mform->addElement('select', 'grade', get_string('grade'), array('1'=>'1', '2'=>'2', '3'=>'3', '4'=>'4', '5'=>'5'));
        $mform->setDefault('grade', 5);
        
        $mform->addElement('select', 'grademethod', get_string('grademethod', "mediaboard"), array('default'=>get_string('default', "mediaboard"), 'rubrics'=>get_string('rubrics', "mediaboard"), 'like'=>get_string('thisnewlike', "mediaboard")));
        $mform->setDefault('grademethod', 'default');


        $mform->addElement('header', 'photos_box', get_string('photosettings', 'mediaboard'));

        $mform->addElement('select', 'allowstudentmediaboard', get_string('mediaboard_allowstudentmediaboard', 'mediaboard'), Array("yes"=>"yes", "no"=>"no"));
        
        $mform->addElement('select', 'multiplechoicequestions', get_string('mediaboard_multiplechoicequestions', 'mediaboard'), Array('yes' => 'yes', 'no' => 'no' ));
        
        $mform->addElement('select', 'allowcomment', get_string('mediaboard_allowcomment', 'mediaboard'), Array("yes"=>"yes", "no"=>"no"));
        
        $mform->addElement('select', 'maxupload', get_string('mediaboard_maxupload', 'mediaboard'), Array("0"=>"Unlimited", "1"=>"1", "2"=>"2", "3"=>"3", "4"=>"4", "5"=>"5", "6"=>"6", "7"=>"7", "8"=>"8", "9"=>"9", "10"=>"10"));
        
        $mform->addElement('select', 'presetimages', get_string('presetimages', 'mediaboard'), Array(0=>"no", 1=>"yes"), 'onchange="fpresetimages();return false;"');
        $mform->setDefault('presetimages', 0);
        
        
        
        $fmstime = 'tmp';
        
        $mediadata = '
            <style type="text/css">
            .showarrow.hover {text-decoration:underline;color: #C7D92C;}
            </style>
            <script type="text/javascript" src="'.$CFG->wwwroot.'/mod/mediaboard/js/jquery.min.js"></script>
            <script type="text/javascript" src="'.$CFG->wwwroot.'/mod/mediaboard/js/ajaxupload.js"></script>
            <script language="JavaScript">
function activateajaximagesuploading() {';
  
        $unicalid = substr(time(), 2);
        $unicals  = array();
  
              for($i=1;$i<=10;$i++) {
                $unicals[] = $unicalid.($i-1);
                
                $mediadata .= '
      new AjaxUpload(\'attachment_upload_'.$fmstime.'_'.$i.'\', {
        action: \''.$CFG->wwwroot.'/mod/mediaboard/uploadimageajax.php\',
        data: {
          \'unical\' : '.$unicals[($i-1)].',
          \'name\' : \'presetimage_'.$i.'\'
        },
        name: \'presetimage_'.$i.'\',
        autoSubmit: true,
        responseType: false,
        onSubmit: function(file, extension) {
          jQuery(\'#slide_preview_'.$i.'\').html(\'<img src="'.$CFG->wwwroot.'/mod/mediaboard/img/ajax-loader.gif" alt="loadeing"/>\');
        },
        onComplete: function(file, response) {
          console.log(response);
          var randomnumber=Math.floor(Math.random()*1100);
          jQuery(\'#slide_preview_'.$i.'\').html(\'<img src="'.$CFG->wwwroot.'/mod/mediaboard/showslidepreview.php?id=\'+response+\'&random=\' +randomnumber+ \'" alt=" " width="150"/>\');
        }
      });';
              }
      
            $mediadata .= '};
              </script>';
            
            
            foreach($unicals as $k => $v){
              $mform->addelEment('hidden', 'unicals['.$k.']', $v);
            }
            
            
            $mform->addElement('static', 'description', '', $mediadata);

            $countofslides[0] = "Select";
        
            for ($i=1; $i<= 10; $i++) {
                $countofslides[$i] = $i;
            }
            
            if (!empty($update)) {
              $instancehtml = ", instance: {$update}";
            } else 
              $instancehtml = "";

            $mform->addElement('html', '<div id="recorsfields" style="display:none">');
            $mform->addElement('html', '<script language="JavaScript">
            function ajaxselector(a) {
              $.post("'.$CFG->wwwroot.'/mod/mediaboard/recordsforms2.php", { slides: a.options[a.selectedIndex].value, userid: "'.$USER->id.'", fmstime: "'.$fmstime.'" }, function(data){$("#recorsfields2").html(data); activateajaximagesuploading();});
            }
            function fpresetimages(){
              if($(\'#id_presetimages\').val() == 1){
                $(\'#recorsfields\').show();
                $(\'#recorsfields2\').show();
              } else {
                $(\'#recorsfields\').hide();
                $(\'#recorsfields2\').hide();
              }
            }
            
            $(document).ready(function() {
              if($(\'#id_type\').val() == \'photo\') {
                $(\'#photos_box\').show();
                $(\'#videos_box\').hide();
              } else {
                $(\'#videos_box\').show();
                $(\'#photos_box\').hide();
              }
              fpresetimages();
              if($(\'#id_slides\').val() > 0) {
                $.post("'.$CFG->wwwroot.'/mod/mediaboard/recordsforms2.php", { slides: $(\'#id_slides\').val(), cid: '.$COURSE->id.' '.$instancehtml.' , userid: "'.$USER->id.'", fmstime: "'.$fmstime.'" }, function(data){$("#recorsfields2").html(data); activateajaximagesuploading();});
              }
            });
            $(\'#id_type\').change(function() {
              if($(\'#id_type\').val() == \'photo\') {
                $(\'#photos_box\').show();
                $(\'#videos_box\').hide();
              } else {
                $(\'#videos_box\').show();
                $(\'#photos_box\').hide();
              }
            });
            </script>');
            
            $mform->addElement('select', 'slides', get_string('mediaboard_selectslides', 'mediaboard'), Array("0"=>"Select", "1"=>"1", "2"=>"2", "3"=>"3", "4"=>"4", "5"=>"5", "6"=>"6", "7"=>"7", "8"=>"8", "9"=>"9", "10"=>"10"), 'onchange="ajaxselector(this);return false;"');
            
            $mform->addElement('html', '</div>');
            $mform->addElement('html', '<div id="recorsfields2"></div>');
            
            
            $mform->addElement('header', 'videos_box', get_string('videosettings', 'mediaboard'));
            $choices = get_max_upload_sizes($CFG->maxbytes, $COURSE->maxbytes);
            $choices[0] = get_string('courseuploadlimit') . ' ('.display_size($COURSE->maxbytes).')';
            $mform->addElement('select', 'maxbytes', get_string('maximumsize', 'assignment'), $choices);
            $mform->setDefault('maxbytes', $CFG->assignment_maxbytes);
            
//-------------------------------------------------------------------------------
        $this->standard_coursemodule_elements();
//-------------------------------------------------------------------------------
        $this->add_action_buttons();

    }
}


