<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly


class wpinfectlitescanner_MalwareScannerLite
{
    
    private $extension = array( '.jpg', '.jpeg', '.png', '.gif', '.svg', '.crt', '.pem','.pdf', '.bmp', '.zip', '.sql', '.jpg', '.po', '.mo', '.otf', '.lha', '.rar','.wpress','.BIN','.mmdb','.gz','.mp4','.ogg','.mov','.psd','.ai','.swp','.log','.wav','.mp3','.backup','.eot','.ttf','.woff','.woff2','.scss','.webp','.css','.backup');
    

    public function wpinfectlitescan_dbinstall() {
        global $wpdb;
        $wpinfectlitescanner_thedbversion= '1.1';

        $table_name = $wpdb->prefix . 'infectscannerlitedata';
        
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE ".$table_name." (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            filepath varchar(1024) DEFAULT '',
            filename varchar(256) DEFAULT '',
            filehash varchar(256) DEFAULT '',
            size  mediumint(9) NOT NULL,
            lastchecked datetime,
            dataadddate datetime,
            infectedflag tinyint DEFAULT 0,
            matchline varchar(1024) DEFAULT '',
            autoremoval varchar(4064) NULL,
            INDEX filepath (filepath),
            INDEX filename (filename),
            INDEX filehash (filehash),
            INDEX lastchecked (lastchecked),
            PRIMARY KEY  (id)
        ) ".$charset_collate.";";
        
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
        
        $oldwpinfectlitescanner_thedbversion = get_option( 'wpinfectlitescanner_thedbversion',false);
        
        if($oldwpinfectlitescanner_thedbversion===false){
            add_option('wpinfectlitescanner_thedbversion', $wpinfectlitescanner_thedbversion );
        }else{
            update_option( 'wpinfectlitescanner_thedbversion', $wpinfectlitescanner_thedbversion );
        }
    }
    

    private $patternsraw = array();
    
    private $wptopdir = "";
    private $iscron = false;
    private $keikajikan = 0;
    private $max_time;
    public $timezone;
    
    
    private function loadPatternsu()
    {
        
        $txt = file_get_contents(__DIR__ . "/malwarepatterns.json");
        $decript = json_decode($txt);
        
        $decript = $decript->data;
        
        $list = array();
        if(! is_array($decript)){
            $decript = array();
        }
        for ($i = 0; $i < count($decript); $i++) {
            $list[] = $decript[$i];
        }
        
        return $list;
    }
    
    private function loadWhitelistu()
    {
        $txt     = file_get_contents(__DIR__ . "/whitelist.json");
        $decript = json_decode($txt);
        $list    = array();
        if(! is_array($decript)){
            return $list;
        }

        return $decript;
    }
    
    public function run($dir,$iscron,$maxtime)
    {
        
        $this->iscron = $iscron;
        $this->keikajikan = microtime(true);
        
        @ini_set("max_execution_time",$maxtime);
        $this->max_time = $maxtime;
        
        if($this->iscron){
            $setting_autoscan = get_option( 'wpinfectlitescanner_cron_autoscan_info');
            if($setting_autoscan!=1){
                return;
            }
            $setting_autoscantime = intval (get_option( 'wpinfectlitescanner_cron_starttime_info'));
            $nowtime = intval (date_i18n ("H"));
            if($nowtime >= $setting_autoscantime && $nowtime <= $setting_autoscantime + 10){
            } else {
                return;
            }
        }
         
        $dir = rtrim($dir, '/');
        if (!is_dir($dir)) {
            if(!$this->iscron){
                return 'error:'. esc_html(__('The directory was not applicable:',"wpinfecscanlite"));
            }
            exit();
        }
        
        $firstrun = true;
        global $wpdb;
        $table_name = $wpdb->prefix . 'infectscannerlitedata';
        $query = $wpdb->prepare("SHOW TABLES LIKE %s", $table_name);
        if($wpdb->get_var($query) != $table_name) { ////edited
            $this->wpinfectlitescan_dbinstall();
            if($wpdb->get_var($query) != $table_name) { ////edited
                if(!$this->iscron){
                    return "error:". esc_html(__("Database creation failed and the scan could not be performed. Please check if this mysql user has permission to create database table.","wpinfecscanlite"));
                }
                return;
            }
        } else {
            $wpinfectlitescanner_thedbversion = get_option( 'wpinfectlitescanner_thedbversion',1.0);
            if($wpinfectlitescanner_thedbversion < 1.1){
                $this->wpinfectlitescan_dbinstall();
            }
            
            $query = $wpdb->prepare("SELECT * FROM %1s where infectedflag > 0;",$table_name);
            $rowsfiles = $wpdb->get_results($query); ////edited

            foreach ($rowsfiles as $row) 
            {
                if(! file_exists ( $dir.$row->filepath.$row->filename )){
                    $sqld = $wpdb->prepare("DELETE FROM `%1s` WHERE `%1s`.`id` = %d",$table_name,$table_name,$row->id);
                    $wpdb->get_results($sqld); ////edited
                }
            }
            
            $firstrun = false;
        }
        
        $this->stat['files_infected']=0;
        $this->stat['directories']=0;
        $this->stat['files_scanned']=0;
        
        if($this->iscron){
            $datebeforeoneday = date("Y-m-d H:i:s", strtotime('-24 hours', time()));
            
            $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where lastchecked < %s;",$table_name,$datebeforeoneday);
            $rows = $wpdb->get_var($query); ////edited
            if ($rows ==0 && !$firstrun){
                return;
            }
        }
        
        $this->wptopdir = $dir;
        $start = time();

        $this->patternsraw = $this->loadPatternsu(false);
        $this->whitelist = $this->loadWhitelistu();

        if(count($this->patternsraw)<10){
            if(!$this->iscron){
                return "error:". esc_html(__("Cannot read malware patterns. Please reinstall plugin.","wpinfecscanlite"));
            }
            return;
        }
        
        $this->process($dir . '/');
        
        
        if(!$this->iscron){

            return $this->report($start, $dir . '/');
            
        } else {
            
            $lastsend = get_option( 'wpinfectlitescanner_cron_lastemailsend_info');
            $sendok = 0;
            if(strlen($lastsend)<5){
                update_option( 'wpinfectlitescanner_cron_lastemailsend_info', date("Y-m-d H:i:s") );
                $sendok = 1;
            } else {
                $from = strtotime($lastsend); 
                $to   = strtotime(date("Y-m-d H:i:s")); 
                $dif = $to - $from;
                if($dif>60*60*24){
                    update_option( 'wpinfectlitescanner_cron_lastemailsend_info', date("Y-m-d H:i:s") );
                    $sendok = 1;
                }
                
            }
            $setting_email = get_option( 'wpinfectlitescanner_cron_mailsend_info' ,-1 );
            

            if($sendok==1 && $setting_email==1 && $this->stat['files_infected'] > 0){
                $setting_emailaddr = get_option( 'wpinfectlitescanner_cron_mailaddr_info',-1  );
                if(is_email($setting_emailaddr)){
                    $end = time();
                    
                    $site_title = get_bloginfo( 'name' );
                    $surl = get_site_url();
                    $message = $site_title."(".$surl.")".esc_html(__(" Please check the malware detected.","wpinfecscanlite"))."\n";
                    $message.= "\n\n";
                    $message.= esc_html(__("Inspection result","wpinfecscanlite"))."\n";
                    $message.= esc_html(__("Beginning time:","wpinfecscanlite")).' ' . strftime('%Y-%m-%d %H:%M:%S', $start) ."\n";
                    $message.= esc_html(__("End time:","wpinfecscanlite")).' ' . strftime('%Y-%m-%d %H:%M:%S', $end) ."\n";
                    $message.= esc_html(__("Duration for scanning:","wpinfecscanlite")).' ' . ($end - $start) .esc_html(__("Seconds","wpinfecscanlite"))."\n";
                    $message.= esc_html(__("Directories scanned:","wpinfecscanlite")).' ' . $dir ."\n";
                    $message.= esc_html(__("The number of directories scanned:","wpinfecscanlite")).' ' . $this->stat['directories'] ."\n";
                    $message.= esc_html(__("The number of files scanned (Files that have changed contents or have passed for a certain period since the last inspection):","wpinfecscanlite")).' ' . $this->stat['files_scanned'] ."\n";
                    $message.= esc_html(__("Unreliable files (malware, virus) found:","wpinfecscanlite")).' ' . $this->stat['files_infected'] ."\n";
        
                    wp_mail( $setting_emailaddr, $site_title.esc_html(__(" Please check the malware detected.","wpinfecscanlite")), $message );
                }
            }
    
        }
    }
    
    private function inWhitelist($hash)
    {
        if(in_array($hash, $this->whitelist)){
            return true;
        }
        $userwhitelist = get_option( 'wpinfectlitescanner_userwhitelist',"");
        if($userwhitelist==""){
            return false;
        }else{
            if(! is_array($userwhitelist)){
				$userwhitelist = unserialize($userwhitelist);
            }
            foreach($userwhitelist as $ws){
                if($ws[2]==$hash){
                    return true;
                }
            }
        }
        return false;
    }
    
    private function process($dir)
    {
        $jtime = microtime(true) - $this->keikajikan;
        if($jtime>$this->max_time*0.8){
            return;
        }
        
        $dirnotexists = false;
        $dh = opendir($dir);
        if (!$dh || count(scandir($dir)) <= 2) {
            $dirnotexists = true;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'infectscannerlitedata';
        $filepathname = str_replace($this->wptopdir,"",$dir);
        
        if($dirnotexists){
            
            if(strlen($filepathname)>0){
                $querydeletefolderdata = $wpdb->prepare("DELETE FROM `%1s` WHERE filepath = %s;",$table_name,$filepathname);
                $wpdb->get_results($querydeletefolderdata); ////edited
            }
            
            return;
        }
        
        $scanthisfolder = false;
        
        //V1
        $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where filepath = %s;",$table_name,$filepathname);
        $rows = $wpdb->get_var($query); ////edited
        
        
        if ($rows==0){
            $scanthisfolder = true;
        } else {
            $datebeforeoneday = date("Y-m-d H:i:s", strtotime('-12 hours', time()));
            $query = $wpdb->prepare("SELECT id,filename FROM %1s where filepath = %s and lastchecked < %s;",$table_name,$filepathname,$datebeforeoneday);
            
            $rowsfiles = $wpdb->get_results($query); ////edited
            if ($wpdb->num_rows>0){
                
                foreach ($rowsfiles as $row) 
                {
                    if(! file_exists ( $dir.$row->filename )){
                        $sqld = $wpdb->prepare("DELETE FROM `%1s` WHERE `%1s`.`id` = %d",$table_name,$table_name,$row->id);
                        $wpdb->get_results($sqld); ////edited
                    }
                    
                }
                
                $scanthisfolder = true;
            } else {
                $query = $wpdb->prepare("SELECT COUNT(id) FROM %1s where filepath = %s and infectedflag > 0;",$table_name,$filepathname);
                $rows = $wpdb->get_var($query); ////edited
                if ($rows>0){
                    $scanthisfolder = true;
                }
            }
        }
        
        if($scanthisfolder){
            
            if(strpos($filepathname,'cache') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'ithemes-security/logs') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'plugins/social-link-machine') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/awstat') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/nfwlog') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/uploads/backwpup') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/wflogs') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/qa-heatmap-analytics-data') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'webalizer') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/awstats') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'uploads/wp-cerber') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'/.git') !== false){
                $scanthisfolder=false;
            }
            
            if(strpos($filepathname,'_sucuribackup.') !== false){
                $scanthisfolder=false;
            }
            
        }
        
        if($scanthisfolder){
            $this->stat['directories']++;
        }
        
        while (($file = readdir($dh)) !== false) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            if (is_link($dir . $file)) {
                continue;
            }
            if (is_dir($dir . $file)) {
                $this->process($dir . $file . '/');
            } elseif (is_file($dir . $file) && $scanthisfolder) {
                $ext    = strtolower(substr($file, strrpos($file, '.')));
                $goscan = true;
                
                if($ext==".jpg" || $ext==".gif"){
                    $filesizejpggif = @filesize($dir . $file);
                    if($filesizejpggif !== false && $filesizejpggif > 0 && $filesizejpggif < 8000){
                        
                    }else{
                        $goscan = false;
                    }
                }else{
                    for ($i = 0; $i < count($this->extension); $i++) {
                        if ($this->extension[$i] == $ext) {
                            $goscan = false;
                            break;
                        }
                    }
                }
                
                if (preg_match("/[0-9]{3,4}x[0-9]{3,4}\.php/", $file)) {
                    $goscan = false;
                }
                
                if (preg_match("/.*log[^\.]*\.txt/i", $file)) {
                    $goscan = false;
                }

                $path = $dir . $file;
                if(@filesize($path)>1048576){
                    $goscan = false;
                }
                
                if ($goscan) {
                    
                    $filesize   = 0;
                    $path = $dir . $file;
                    $fileContent = file_get_contents($path);
                    $filesize = strlen($fileContent);
                    $hash = md5($fileContent);
                                    
                    if(empty($fileContent)){
                        

                        $query = $wpdb->prepare("SELECT * FROM %1s where filepath = %s and filename = %s LIMIT 1;",$table_name,$filepathname,$file);  
                        
                        $rows = $wpdb->get_results($query); ////edited
                        if($wpdb->num_rows>0){
                            foreach ($rows as $row) 
                            {
                                $dateyhisday = date("Y-m-d H:i:s");
                                
                                $sql = $wpdb->prepare("UPDATE `%1s` SET `lastchecked` = %s, filehash=%s,size='%d',infectedflag=0 WHERE `%1s`.`id` = %d;",$table_name,$dateyhisday,$hash,$filesize,$table_name,$row->id);
                                $wpdb->get_results($sql); ////edited
                                
                            }
                        }
                        
                        continue;
                    }
                    
                    if ($filesize > 200000) {
                        
                        $query = $wpdb->prepare("SELECT * FROM %1s where filepath = %s and filename = %s LIMIT 1;",$table_name,$filepathname,$file);  
                        $rows = $wpdb->get_results($query); ////edited
                        if($wpdb->num_rows>0){
                            foreach ($rows as $row) 
                            {
                                $dateyhisday = date("Y-m-d H:i:s");
                                
                                $sql = $wpdb->prepare("UPDATE `%1s` SET `lastchecked` = %s, filehash = %s, size = '%d' WHERE `%1s`.`id` = %d;",$table_name,$dateyhisday,$hash,$filesize,$table_name,$row->id);
                                $wpdb->get_results($sql); ////edited
                            }
                        }
                        
                        continue;
                    }

                    
                    $query = $wpdb->prepare("SELECT * FROM %1s where filehash = %s and filepath = %s and filename =%s LIMIT 1;",$table_name,$hash,$filepathname,$file);
                    $rows = $wpdb->get_results($query); ////edited
                    
                    
                    if($wpdb->num_rows>0){
                        
                        foreach ($rows as $row) 
                        {
                            
                            $dateyhisday = date("Y-m-d H:i:s");
                            
                            $wasinfected = $row->infectedflag;
                            
                            $sql = $wpdb->prepare("UPDATE `%1s` SET `lastchecked` = %s WHERE `%1s`.`id` = %d;",$table_name,$dateyhisday,$table_name,$row->id);
                            
                            $wpdb->get_results($sql); ////edited
                            
                            $infected = $this->scan($path, $fileContent,$hash,$wasinfected);
                            if(! $infected){
                                $sql = $wpdb->prepare("UPDATE `%1s` SET infectedflag = 0  WHERE `%1s`.`id` = %d;",$table_name,$table_name,$row->id);
                                $wpdb->get_results($sql);////edited
                            }else{
                                global $wpinfectlitescanner_lines;
                                $sql = $wpdb->prepare("UPDATE `%1s` SET infectedflag=%d,matchline=%s WHERE `%1s`.`id` = %d;",$table_name,$infected,$wpinfectlitescanner_lines,$table_name,$row->id);
                                $wpdb->get_results($sql);////edited
                            }
                        }
                         
                        
                    } else {
                        
                        $query = $wpdb->prepare("SELECT * FROM %1s where filepath = %s and filename = %s LIMIT 1;",$table_name,$filepathname,$file);
                        
                        $rows = $wpdb->get_results($query); ////edited
                        $rowid = 0;
                        $wasinfected = false;
                        $filechanged = false;
                        $newadded = false;
                        if($wpdb->num_rows>0){
                            foreach ($rows as $row) 
                            {
                                $dateyhisday = date("Y-m-d H:i:s");
                                
                                $sql =  $wpdb->prepare("UPDATE `%1s` SET `lastchecked` = %s, filehash=%s,size=%s  WHERE `%1s`.`id` = %d;",$table_name,$dateyhisday,$hash,$filesize,$table_name,$row->id);
                                
                                $wpdb->get_results($sql); ////edited
                                $rowid = $row->id;
                                $wasinfected = $row->infectedflag;

                            }
                        } else {
                            $dateyhisday = date("Y-m-d H:i:s");
                            $sql = $wpdb->prepare("INSERT INTO `%1s` (`id`, `filepath`, `filename`, `filehash`, `size`, `lastchecked`, `dataadddate`) VALUES (NULL, %s, %s, %s, %d, %s, %s);",$table_name,$filepathname,$file,$hash,$filesize,$dateyhisday,$dateyhisday);
                            $wpdb->get_results($sql);////edited
                            $rowid = $wpdb->insert_id;
                            $newadded = true;
                        }
                        $infected = $this->scan($path, $fileContent,$hash,$wasinfected);
                        
                        if(! $infected){

                            if($wasinfected>0){
                                $sql = $wpdb->prepare("UPDATE `%1s` SET infectedflag=0,matchline=''  WHERE `%1s`.`id` = %d;",$table_name,$table_name,$rowid);
                                $wpdb->get_results($sql);////edited
                                
                            } 
                            
                        }else{
                            
                            global $wpinfectlitescanner_lines;
                            $sql = $wpdb->prepare("UPDATE `%1s` SET infectedflag = %d, matchline = %s WHERE `%1s`.`id` = %d;",$table_name,$infected,$wpinfectlitescanner_lines,$table_name,$rowid);
                            $wpdb->get_results($sql);////edited
                            
                        }
                        
                    }
                }
            }
        }
        closedir($dh);
    }
    
    private function report($start, $dir)
    {
        return "doneok:".$this->stat['directories'].":".$this->stat['files_scanned'].":".$this->stat['files_infected'];
    }
    
    private function scan($path,$fileContent,$hash,$wasinfected)
    {
        
        usleep(1000);
        
        $this->stat['files_scanned']++;
        
        if ($this->inWhitelist($hash)) {
            return false;
        }
        
        $found     = false;
        $toSearch  = '';
        $linetxt   = '';
        $patternid = '';
        global $wpinfectlitescanner_lines;
        $wpinfectlitescanner_lines = "";
        $myfilename = str_replace($this->wptopdir,"",$path); 
        $matchedcount = 0;
        
        $fileContent_sr = str_replace("\r\n", "\n ", $fileContent);
        $fileContent_sr = str_replace("\r", "\n", $fileContent_sr);
        $fileContent_sr = str_replace(" ", "", $fileContent_sr);
        $fileContent_sr = str_replace("\t", "", $fileContent_sr);

        
        foreach ($this->patternsraw as $toSearch) {
            
            $nowpattern = $toSearch->without_whitespace_pattern;
            $substrCount = false;

            $substrCount = strpos($fileContent_sr,$nowpattern );
            
            if ($substrCount !== false) {
               
                $fileContent_s = $fileContent_sr;
                
                preg_match_all('/' . preg_quote($nowpattern, '/') . '/s', $fileContent_s, $m);
                $patternid .= $toSearch->id.",";
                
                for ($i = 0; $i < count($m[0]); $i++) {
                    
                    $matchedcount++;
                    
                    @mb_internal_encoding("UTF-8");
                    
                    $pos            = mb_strpos($fileContent_s, $m[0][$i]);
                    $fileContent_ss = mb_substr($fileContent_s, 0, $pos);
                    $linecount      = mb_substr_count($fileContent_ss, "\n") + 1;
                    
                    $wpinfectlitescanner_lines .= $linecount.",";
                    
                    $reptct  = "";
                    for ($ix = 0; $ix < strlen($m[0][$i]); $ix++) {
                        $reptct .= " ";
                    }
                    
                    $fileContent_s = preg_replace("/" . preg_quote($m[0][$i], '/') . "/", $reptct, $fileContent_s, 1);
                    $found         = true;
                    
                }
            }
        }
        
        
        if (!$found) {
            return false;
        }
                                                                   
        $this->stat['files_infected']++;
        
        return 1;
    }
    
    public function onefilescan($fileContent,$hash)
    {
        $this->patternsraw = $this->loadPatternsu(false);
        $this->whitelist = $this->loadWhitelistu();
        
        $found     = false;
        
        $fileContent_sr = str_replace("\r\n", "\n ", $fileContent);
        $fileContent_sr = str_replace("\r", "\n", $fileContent_sr);
        $fileContent_sr = str_replace(" ", "", $fileContent_sr);
        $fileContent_sr = str_replace("\t", "", $fileContent_sr);

        foreach ($this->patternsraw as $toSearch) {
            
            $nowpattern = $toSearch->without_whitespace_pattern;
            $substrCount = strpos($fileContent_sr,$nowpattern );
            $matchcount = 0;
            
            if ($substrCount !== false || $matchcount > 0) {
                $found         = true;
                break;
            }
        }
        
        if (!$found) {
            return false;
        }
        
        if ($found && $this->inWhitelist($hash)) {
            return false;
        }
        
        
        return true;
    }
    
}

?>