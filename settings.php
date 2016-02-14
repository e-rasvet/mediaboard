<?php

defined('MOODLE_INTERNAL') || die;

if ($ADMIN->fulltree) {
    require_once($CFG->dirroot.'/mod/mediaboard/lib.php');

    if (isset($CFG->maxbytes)) {
        $settings->add(new admin_setting_configselect('mediaboard_maxbytes', get_string('maximumsize', 'mediaboard'),
                           get_string('configmaxbytes', 'mediaboard'), 1048576, get_max_upload_sizes($CFG->maxbytes)));
    }

    $options = array(mediaboard_COUNT_WORDS   => trim(get_string('numwords', '', '?')),
                     mediaboard_COUNT_LETTERS => trim(get_string('numletters', '', '?')));
    $settings->add(new admin_setting_configselect('mediaboard_itemstocount', get_string('itemstocount', 'mediaboard'),
                       get_string('configitemstocount', 'mediaboard'), mediaboard_COUNT_WORDS, $options));

    $settings->add(new admin_setting_configcheckbox('mediaboard_showrecentsubmissions', get_string('showrecentsubmissions', 'mediaboard'),
                       get_string('configshowrecentsubmissions', 'mediaboard'), 1));
                       
    // Converting method
    $options = array();
    $options[1] = get_string('usemediaconvert', 'mediaboard');
    $options[2] = get_string('usethisserver', 'mediaboard');
    $settings->add(new admin_setting_configselect('mediaboard_audio_convert',
            get_string('convertmethod', 'mediaboard'), get_string('descrforconverting', 'mediaboard'), 1, $options));
            
    // Converting method video
    $options = array();
    $options[1] = get_string('usemediaconvert', 'mediaboard');
    $options[3] = get_string('useyoutube', 'mediaboard');
    $options[4] = get_string('noconversionfiles', 'mediaboard');
    $settings->add(new admin_setting_configselect('mediaboard_video_convert',
            get_string('convertmethodvideo', 'mediaboard'), get_string('descrforconverting', 'mediaboard'), 1, $options));
            
    // Converting url
    $settings->add(new admin_setting_configtext('mediaboard_convert_url',
            get_string('converturl', 'mediaboard'), get_string('descrforconvertingurl', 'mediaboard'), '', PARAM_URL));
            
    // YouTube email
    $settings->add(new admin_setting_configtext('mediaboard_youtube_email',
            get_string('youtube_email', 'mediaboard'), get_string('descrforyoutube_email', 'mediaboard'), '', PARAM_EMAIL));
            
    // YouTube password
    $settings->add(new admin_setting_configtext('mediaboard_youtube_password',
            get_string('youtube_password', 'mediaboard'), get_string('descrforyoutube_password', 'mediaboard'), '', PARAM_TEXT));
            
    // YouTube ApiKey
    $settings->add(new admin_setting_configtext('mediaboard_youtube_apikey',
            get_string('youtube_apikey', 'mediaboard'), get_string('descrforyoutube_apikey', 'mediaboard'), '', PARAM_TEXT));
}
