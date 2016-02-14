# v 1.0 2010/07/09 12:29:00 Igor Nikulin

CREATE TABLE `prefix_mediaboard` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `name` varchar(255) NOT NULL default '',
  `summary` text NOT NULL default '',
  `timeopen` int(10) unsigned NOT NULL default '0',
  `timeclose` int(10) unsigned NOT NULL default '0',
  `course` varchar(255) NOT NULL default '',
  `teacher` varchar(255) NOT NULL default '',
  `multiplechoicequestions` varchar(255) NOT NULL default 'no',
  `quizid` int(10) unsigned NOT NULL default '0',
  `maxupload` int(10) unsigned NOT NULL default '0',
  `allowcomment` varchar(3) NOT NULL default 'no',
  `allowstudentmediaboard` varchar(3) NOT NULL default 'no',
  `time` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) COMMENT='mediaboard';

CREATE TABLE `prefix_mediaboard_files` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `instance` int(10) unsigned NOT NULL default '0',
  `name` varchar(255) NOT NULL default '',
  `userid` int(10) unsigned NOT NULL default '0',
  `groupid` int(10) unsigned NOT NULL default '0',
  `text` text NOT NULL default '',
  `multiplechoicequestions` varchar(255) NOT NULL default 'no',
  `file` varchar(255) NOT NULL default 'no',
  `timemodified` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) COMMENT='mediaboard files';

CREATE TABLE `prefix_mediaboard_comments` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `instance` int(10) unsigned NOT NULL default '0',
  `userid` int(10) unsigned NOT NULL default '0',
  `fileid` int(10) unsigned NOT NULL default '0',
  `text` text NOT NULL default '',
  `timemodified` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) COMMENT='mediaboard files comments';

CREATE TABLE `prefix_mediaboard_questions` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `instance` int(10) unsigned NOT NULL default '0',
  `fileid` int(10) unsigned NOT NULL default '0',
  `name` varchar(255) NOT NULL default '',
  `userid` int(10) unsigned NOT NULL default '0',
  `timemodified` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) COMMENT='mediaboard questions';


CREATE TABLE `prefix_mediaboard_choice` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `questionid` int(10) unsigned NOT NULL default '0',
  `name` varchar(255) NOT NULL default '',
  `grade` varchar(255) NOT NULL default '0',
  `timemodified` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) COMMENT='mediaboard choice';


CREATE TABLE `prefix_mediaboard_answer` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `questionid` int(10) unsigned NOT NULL default '0',
  `userid` int(10) unsigned NOT NULL default '0',
  `answerid` varchar(255) NOT NULL default '',
  `grade` varchar(255) NOT NULL default '',
  `timemodified` int(10) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) COMMENT='mediaboard choice';
# --------------------------------------------------------
