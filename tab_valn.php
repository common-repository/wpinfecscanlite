<?php if ( ! defined( 'ABSPATH' ) ) {exit;}?>
<div class="tab-pane" id="ContentE">

    <div class="col-lg-12">
        
        <p><?php esc_html_e("This vulnerability checker will check if there are valunability in your site's plugin and wordpress. This function checks most used valunability for hacking that has over CVSS 9.0 point. Detects approximately 500 vulnerabilities created by the NIST vulnerability database in September 2024. Please use the Pro version to inspect for the latest and more(Over 2000) vulnerabilities.","wpinfecscanlite");?>
        </p>

        <br>
        
        <div style="margin-bottom:20px;">
        
        <button class="btn btn-danger" id='valtestbutton'><?php esc_html_e("Run vulnerability checker","wpinfecscanlite");?></button>
        <div id="scanningnow" style="display:none"><i class="fa fa-circle-o-notch fa-spin"></i> <?php esc_html_e("Checking valunability now...","wpinfecscanlite");?></div>
        
        </div>
        <?php
        $lastchecktime = get_option( 'wpinfectlitescanner_valnchecktime', "" );
        if(! empty($lastchecktime)){
            echo "<h4 id='valntitle'>".esc_html(__("Last vulnerability check result","wpinfecscanlite"))." (".esc_html($lastchecktime).")</h4>";
        }else{
            echo "<h4 id='valntitle'></h4>";
        }
        ?>
        <table class="table">
            <thead>
                <tr>
                    <th><?php esc_html_e('Name', "wpinfecscanlite") ?></th>
                    <th><?php esc_html_e('Type', "wpinfecscanlite") ?></th>
                    <th><?php esc_html_e('Version', "wpinfecscanlite") ?></th>
                    <th><?php esc_html_e('Status', "wpinfecscanlite") ?></th>
                    <th><?php esc_html_e('Valunability', "wpinfecscanlite") ?></th>
                </tr>
            </thead>
            <tbody id="tbodychecked">
            
            <?php
            
            $sitevdata = array();
            global $wp_version;
            $sitevdata[] = array("wordpress","wordpress",esc_html($wp_version),"WordPress");
            
            $my_plugin = WP_PLUGIN_DIR;
            $folders = glob($my_plugin."/*", GLOB_ONLYDIR);
            foreach ($folders as $folder) {
                $files = scandir($folder."/"); 
                $foundfile=false;
                $pluginfolder=basename($folder);
                $pluginname="";
                $pluginversion="";
                foreach($files as $file)
                {
                    $path_parts = pathinfo($folder."/".$file);
                    if(isset($path_parts['extension'])){
                        if(is_file($folder."/".$file) && $path_parts['extension']=="php"){
                            if (! @ini_get("auto_detect_line_endings")) {
                                @ini_set("auto_detect_line_endings", '1');
                            }
                            $fn = fopen($folder."/".$file,"r");
                            if($fn){
                                $readcount = 0;
                                while(! feof($fn))  {
                                    $result = fgets($fn);
                                    if(strpos($result,"Plugin Name:")!== false || strpos($result,"Plugin Name :")!== false){
                                        $foundfile=true;
                                        $pluginname=explode(":",$result);
                                        $pluginname=trim($pluginname[1]);
                                    }
                                    if(strpos($result,"Version:")!== false || strpos($result,"Version :")!== false){
                                        $foundfile=true;
                                        $pluginversion=explode(":",$result);
                                        $pluginversion=trim($pluginversion[1]);
                                    }
                                    $readcount++;
                                    if($readcount>20){
                                        break;
                                    }
                                }
                                fclose($fn);
                            }
                        }
                    }
                    if($foundfile){
                        break;
                    }
                }
                if($pluginfolder!="" && $pluginname!="" && $pluginversion!=""){
                    $sitevdata[] = array(esc_html($pluginfolder),"plugin",esc_html($pluginversion),esc_html($pluginname));
                }
            }
            
            $lastcheckdata = get_option( 'wpinfectlitescanner_valncheck', -1 );
            if($lastcheckdata!=-1){
                $checkeddata = json_decode($lastcheckdata,false);
                if($checkeddata){
                    foreach($checkeddata as $cdata){
                        
                        $type = $cdata[1];
                        $version = $cdata[2];
                        $valn=$cdata[3];
                        $thisname = $cdata[4];
                        $valntxt = esc_html(__("No vulnerability found","wpinfecscanlite"));
                        $cvetxt = "-";
                        $icon="<span class='dashicons dashicons-yes' style='color:green'></span>";
                        if($valn!="0"){
                            $valntxt= esc_html(__("Vulnerability found","wpinfecscanlite"));
                            $cvetxt = "";
                            $valnar=explode(",",$valn);
                            for($vi=0;$vi<count($valnar);$vi++){
                                $cve=trim($valnar[$vi]);
                                if(! empty($cve)){
                                    $cvetxt .= "<a href='https://nvd.nist.gov/vuln/detail/".esc_html($cve)."' target='_blank'>".esc_html($cve)."</a><br>";
                                }
                            }
                            $icon="<span class='dashicons dashicons-no' style='color:red'></span>";
                        }
                        echo "
                        <tr class='valnonedata'>
                            <td>".$icon." <b>".esc_html($thisname)."</b></td>
                            <td>".esc_html($type)."</td>
                            <td>".esc_html($version)."</td>
                            <td>".esc_html($valntxt)."</td>
                            <td>".$cvetxt."</td>
                        </tr>";
                    }
                }
                
            }else{
            ?>
                
                <?php
                foreach ($sitevdata as $onesitevdata){
                    //$pluginfolder,"plugin",$pluginversion,$pluginname
                ?>
                    <tr class='valnonedata'>
                        <td><b><?php echo esc_html($onesitevdata[3]);?></b></td>
                        <td><?php echo esc_html($onesitevdata[1]);?></td>
                        <td><?php echo esc_html($onesitevdata[2]);?></td>
                        <td><?php esc_html_e('Not checked', "wpinfecscanlite") ?></td>
                        <td>-</td>
                    </tr>
                <?php
                }
            }
            ?>
            </tbody>
        </table>
        
        <script>
            var senddata = '<?php echo str_rot13(bin2hex(json_encode($sitevdata))) ;?>';
            jQuery('#valtestbutton').click(function() {
                jQuery('#valtestbutton').hide();
                jQuery('#scanningnow').show();
                jQuery.ajax({
                   type: "POST",
                   url: "<?php echo admin_url( 'admin-ajax.php'); ?>",
                   data: "chackdata="+senddata+"&action=wpinfectlitescanner_valncheck&nonce=<?php echo esc_html(wp_create_nonce('wpinfecscanlite')); ?>",
                   success: function(msg){
                       
                       if(msg.length<5){
                           alert("<?php echo esc_html(__("Vulnerability check failed","wpinfecscanlite")); ?>");
                       }else{

                           var objJSON = JSON.parse(msg);
                           
                           if(objJSON.length>0){
                               jQuery(".valnonedata").remove();
                               jQuery('#valntitle').html("<?php echo esc_html(__("Valunability check result",'wpinfecscanlite')); ?>");
                               for (var i = 0, len = objJSON.length; i < len; ++i) {
                                     var onedata = objJSON[i];
                                     var valntxt = "<?php esc_html_e('No vulnerability found', "wpinfecscanlite") ?>";
                                     var cvetxt = "-";
                                     var icon="<span class='dashicons dashicons-yes' style='color:green'></span>";
                                     if(onedata[3]!="0"){
                                         cvetxt = "";
                                         valntxt = "<?php esc_html_e('Vulnerability found', "wpinfecscanlite") ?>";
                                         var cvetext = onedata[3];
                                         var cvear = cvetext.split(',');
                                         for (var ii = 0, tlen = cvear.length; ii < tlen-1; ++ii) {
                                             cvetxt = cvetxt + "<a href='https://nvd.nist.gov/vuln/detail/"+cvear[ii]+"' target='_blank'>"+cvear[ii]+"</a><br>";
                                         }
                                         var icon="<span class='dashicons dashicons-no' style='color:red'></span>";
                                     }
                                     jQuery("#tbodychecked").append("<tr class='valnonedata'><td>"+icon+" <b>"+onedata[4]+"</b></td><td>"+onedata[1]+"</td><td>"+onedata[2]+"</td><td>"+valntxt+"</td><td>"+cvetxt+"</td></tr>");
                               }
                           }
                           
                       }
                            
                       jQuery('#valtestbutton').hide();
                       jQuery('#scanningnow').hide();
                   }
                 });
            });
        </script>
    
    </div>
</div>