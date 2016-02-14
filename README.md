********************************************************************************************* 
****** WARNING: THIS MODULE FOR MOODLE 2.2 ****** 
*********************************************************************************************

--------
ABOUT
--------
This is version 2.x of the "mediaboard" module (mediaboard).

2.x release is compatible only with Moodle 2.2

The "mediaboard" module is developed by
    Igor Nikulin, Paul Daniels.

This module may be distributed under the terms of the General Public License
(see http://www.gnu.org/licenses/gpl.txt for details)

-----------
PURPOSE
-----------
This module allows users to create mediaboard simply by uploading images and sound files.
Images can be uploaded or chosen from images that have already been uploaded.
Uploaded MP3 files or voice recorded on line can also be selected for the mediaboard.
The HTML5 mediaboard is created automatically after choosing or uploading the sound and image files.

----------------
INSTALLATION
----------------
The mediaboard follows standard installation procedures.
Place the "mediaboard" directory in your mod directory.
Then visit the Admin page in Moodle to activate it.
Install FFMPEG with lame support
- Installed the libmp3lame from source:
wget http://easynews.dl.sourceforge.net/sourceforge/lame/lame-3.98.4.tar.gz; tar -xvf lame-3.98.4.tar.gz; cd lame-3.98.4;./configure; sudo make && make install
- Removed the pre-compiled ffmpeg installation: apt-get remove ffmpeg
- Downloaded its source: svn checkout svn://svn.ffmpeg.org/ffmpeg/trunk ffmpeg
- Installed the source setting the –enable-libmp3lame option up: sudo ./configure –   -enable-libmp3lame; sudo make && make install
- Bug in Cent OS 5, command for fixing bug : ldconfig /usr/local/lib

Warring! Be careful, you can kill your server if you make a mistake.

----------------
HOW TO USE:
----------------
1. Create a mediaboard activity
2. Enter title, summary, description and number of slides.
3. Add images and voice.