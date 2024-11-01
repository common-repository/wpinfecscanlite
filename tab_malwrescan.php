<?php if ( ! defined( 'ABSPATH' ) ) {exit;}?>

<div class="tab-pane active" id="ContentA">
    <div class="col-lg-12">
            <style>
            .ceditbt {
                display: block;
                position: relative;
                width: 100%;
                padding: 0.8em;
                text-align: center;
                text-decoration: none;
                color: #fff;
                border-radius:5px;
                font-size: 13px;
                white-space:nowrap;
                height: 58px;
            }
            .ceditbt{
                background: #02b762;
                margin-bottom:5px;
            }
            .autorestorebt {
                display: block;
                position: relative;
                width: 100%;
                padding: 0.3em;
                text-align: center;
                text-decoration: none;
                color: #fff;
                border-radius:5px;
                font-size: 13px;
                min-width:110px;
                height:58px;
                background: #adb7b9;
                border:1px solid #888;
                line-height: 100%;
            }
            h4 {
                font-size: 1rem;
                font-weight:bold;
                margin-top:16px;
            }
            .modal-title{
                margin-top:0px;
            }
            p {
                font-size: 1rem;
            }
            </style>

            <?php 
                
                if($scanok){
                    
                    ?>
                     <div class="progress" id="scanprogress">
                      <div class="progress-bar progress-bar-striped progress-bar-animated active" role="progressbar"
                      aria-valuenow="100" aria-valuemin="0" aria-valuemax="100" style="width:100%">
                        <?php echo esc_html(__("Scanning in progress","wpinfecscanlite"));?>
                      </div>
                    </div> 
                    <div style="width:100%">
                        
                        <h4 id="scanprocess"><span class='dashicons dashicons-portfolio' style='font-size: 20px;color:#ffbb51;'></span> <?php echo esc_html(__("The number of files scanned:","wpinfecscanlite"));?> <?php echo esc_html(__("The number of malwares detected:","wpinfecscanlite"));?></h4>
                    </div>
                    <small><?php echo esc_html(__("Inspecting files that have changed contents or have passed for a certain period since the last inspection.",'wpinfecscanlite')); ?></small><br><br>
                    <script>
                    var scanend = false;
                    var infecfilecount = 0;
                    var startTime;
                    var oldscanendfilecount=0;
                    var samefilecount=0;
                    var scanlloptimeout;
                    function scanloop(){
                        startTime = new Date();
                        jQuery.ajax({
                           type: "POST",
                           url: "<?php echo esc_url(admin_url( 'admin-ajax.php')); ?>",
                           data: "action=wpinfectlitescanner_realtimerun&nonce=<?php echo esc_html(wp_create_nonce('wpinfecscanlite'));////edited2 ?>",
                           success: function(msg){
                               var res = jQuery.parseJSON(msg);
                               
                               if(res.status.match(/doneok/) && scanend==false){
                                    var currentTime = new Date();
                                    var status = (currentTime - startTime);
                                    if(status>20000){
                                        scanloop();
                                    }else{
                                        scanlloptimeout=setTimeout("scanloop()",20000-status);
                                    }
                                }
                               
                               if(res.status=="error"){
                                   alert(res.d1);
                                   scanend = true;
                                   jQuery("#scanprogress").hide();
                                   document.getElementById("scank").innerHTML = "<?php echo esc_html(__("Scanning completed!","wpinfecscanlite"));?> ";
                               }
                           }
                         });     
                    }
                    
                    function getprocess(){  
                        jQuery.ajax({
                           type: "POST",
                           url: "<?php echo esc_url(admin_url( 'admin-ajax.php')); ?>",
                           data: "starttime=<?php echo esc_html(date("Y-m-d H:i:s", strtotime('-10 seconds', time()))); ?>&action=wpinfectlitescanner_getscanprocess&nonce=<?php echo esc_html(wp_create_nonce('wpinfecscanlite'));////edited2 ?>",
                           success: function(msg){
                               
                               var res = jQuery.parseJSON(msg);
                               if(res==null){
                                   setTimeout(getprocess,20000);
                               }else{
                                   jQuery("#scanprocess").html(" <span class='dashicons dashicons-portfolio' style='font-size: 20px;color:#ffbb51;'></span> <?php echo esc_html(__("The number of files scanned:","wpinfecscanlite"));?>"+res.d1+" <?php echo esc_html(__("The number of malwares detected:","wpinfecscanlite"));?>"+res.d2);
                                  
                                   infecfilecount=res.d2;
                                   if(res.d2>0){
                                       jQuery("#showinfectfiles").html(res.d3);
                                   }
                                   if(oldscanendfilecount==res.d1){
                                       samefilecount=samefilecount+1;
                                       if(samefilecount>2){
                                            scanend = true;
                                            document.getElementById("scank").innerHTML = "<?php echo esc_html(__("Scanning completed!","wpinfecscanlite"));?> ";
                                            
                                            if(parseInt(infecfilecount)==0){
                                                jQuery("#showinfectfiles").html("<?php 
                                                $hmatchurl = plugin_dir_url( __FILE__ )."images/noinfect.png";
                                                echo "<h4 style='margin-top:25px;margin-bottom:25px;padding:0px;'><img src='".esc_html($hmatchurl)."' style='width:30px;padding:0px;'> ".esc_html(__("Not detected any malware in this website.","wpinfecscanlite"))."</h4>";////edited2 ?>");
                                            }
                                            
                                            jQuery("#scanprogress").hide();
                                            
                                            clearTimeout(scanlloptimeout);
                                       }
                                   }else{
                                       oldscanendfilecount=res.d1;
                                   }
                                   if(scanend==false){
                                        setTimeout(getprocess,15000);
                                   } 
                               }
                           }
                         });     
                    }
                    
                    jQuery(function(){
                            scanloop();   
                            getprocess();                                       
                    });
                    
                    </script>
                    <?php
                    echo '<table id="scanresult" class="table"><thead><tr><th nowrap></th><th>'.esc_html(__("Detected",'wpinfecscanlite'))."</th><th>".esc_html(__("Pattern matching",'wpinfecscanlite'))."</th><th nowrap>".esc_html(__("View code",'wpinfecscanlite')).'</th><th nowrap>'.esc_html(__("White list",'wpinfecscanlite')).'</th></tr></thead>';
                    ?><tbody id="showinfectfiles"></tbody></table>
                    <?php
                } else {
                    
                    include_once('scannerdata/getscanprocess_inc2.php');

                }
            ?>
            <br><br>
        
    </div>
</div>