##########################################################################
#       Script to parse GPO Debugging enabled logs GPSVC.log             #
# It's only to analyze processing of User policy, and NOT Machine policy #
# It's only for testing purpose and not for production use               #
##########################################################################
#                                                                        # 
# The input file need to be in ANSI format                               #
# GPSVC.log was created by default UTF-16 LE format                      #
# Need manually open the file in notepad and save using ANSI encoding    #
# Script is meant to be running in powershell_ISE                        #
########################################################################## 
<# Author: Ken Mei

 LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
 

This script is meant to run from powershel_ISE
This is to analaze GPP client-side extension processing
The Input file must be in ANSI encoding.
please note that default log file is in UTF16-LE format, which needs to be 
manually converted. Easier way to do so is open it with notepad, and save it 

How to capture gpsvc log? By running Tss tool while repo the login
.\TSS.ps1 -Scenario ADS_GPOEx -ADS_GPedit -ADS_GPmgmt -ADS_GPO -ADS_GPsvc -GPresult Both
https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-tss/gather-information-using-tss-group-policy
Or set it up manually
https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events

Enable gpo debug:
md %windir%\debug\usermode
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d "0x00030002"

Disable GPO Debug: 
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d "0x00000000" /f

------------------------------------------------------------------------------------------------------------------------- #>

#input file need to be in ANSI encoding format

$gpsvclogs = Get-Content -Path "c:\sample-path-to-logfle-in-ANSI-encoding-format-gpsvc.log"


# string used to find relevant info
$min_process_time = 0.03  #only list CSE over 30 millisecond
$format = "HH:mm:ss:fff"
$string2 = "List of GPO\(s\)"
$string3 = "returned 0x0"
$string4 = "ProcessGPOList"
$usergpo = "ProcessGPOs\(User\)"
$usernamestr = "ProcessGPOs\(User\)\: Logging Data for Target" 
$cse_matching_str = "ProcessGPOs\(User\)\: Processing"
$completedowngpo_str = "ProcessGPOs\(User\)\: Get"
$delimiter = "Processing extension"
$policy_sets = @()
$username = $null
$list_of_polices=$nul

#function to find the policies if avaiable being processed by each CSE
function find-policies {
  param(
  [array]$array,
  [string]$String,
  [string]$string2
  )
 
 $policies = $null
  for($idx=0; $idx -lt $array.length; $idx++) {
     if ($array[$idx] -match "$string") {
        for($idx2=$idx+1; $idx2 -lt $idx+3; $idx2++){
          if ($array[$idx2] -match "$string2") {
            $policies =(($array[$idx2].split(":"))[-1]).split('""') |Where-Object {$_ -ne ' '}
            break
          }

        }
      
        break
      }
   }

  if ($policies.count -eq 0) {$policies = "no policy found"}

  return $policies
  
}  #end of find index function


#get the different pid/tid, each represent a different sessioin
$sessions = ($gpsvclogs | Where-Object {$_ -match "$usergpo"} | ForEach-Object { ($_.split(" ")[0]).split("(")[1].split(")")[0]} |Select-Object -Unique)

foreach ($session in $sessions) {
   
   $hPID = "0x" +$session.Split('.')[0]
   $hTID = "0x" +$session.Split('.')[1]
   $dPid = [System.Convert]::ToInt32($hPID,16)
   $dTid = [System.Convert]::ToInt32($hTID,16)

   # get logs for each unique session, and total duration of the session
   $session_log = $gpsvclogs |Where-Object {$_ -match "$session"}
   $starttime = $session_log[0].Split("")[1]
   $endtime = $session_log[-1].Split("")[1]
   $total_time = ([datetime]::ParseExact($endtime, $format,$null)).subtract([datetime]::ParseExact($starttime, $format,$null)).totalseconds

   # get number of policy, and their search and download time
   $gposearchdown_time = ($session_log |Where-Object { $_ -match "$completedowngpo_str"}).Split("")[1]
   $numbeofpolices = (($session_log |Where-Object { $_ -match "$completedowngpo_str"}) -Split("get"))[1].Split("")[1]
   $download_time = ([datetime]::ParseExact($gposearchdown_time, $format,$null)).subtract([datetime]::ParseExact($starttime, $format,$null)).totalseconds
  
    # determine how many CES was processed
    $total_CSE = $session_log | Where-Object { $_ -match "$cse_matching_str"} | ForEach-Object { ($_ -csplit "($delimiter)")[-1].trim()}

   #determine each user user if avaiable 
   $usernameline = $session_log  | Where-Object {$_ -match "$usernamestr"}
   if ($usernameline -eq $null) { 
        $username = "No UserName Captured"
   } else {
        $username = $usernameline.split("<")[1].split(">")[0]
   }

   Write-host "<<<<------------------------------------>>>>>"
   Write-host "<<<<------------------------------------>>>>>"
   Write-host "<<<<------------------------------------>>>>>"

   write-host "GPOs processed for this session: UserName: <<$username>> ::<<Pid.Tid(Hex)>>::$session  :: <PID/TID(Decimal)>>::$dPid.$dTid" -ForegroundColor Magenta
   Write-host "--> Totat Duration to process All user policies in seconds:  $total_time"
   write-host
   write-host 
   Write-host "---> Total number of policies and time to search and download: $numbeofpolices policies and  $download_time seconds"
   write-host
   write-host 
  
   foreach ($CSE in $total_CSE) {
           
          if ($CSE -eq 'Registry') {
                $CSE = "extension Registry"
           }

           if ($CSE -eq "CP"){
                $CSE = "extension CP"
           }

           if ($CSE -eq "AdmPwd") {
                $CSE = "extension AdmPwd"
           }
           
           if ($CSE -eq "Security") {
                $CSE = "extension Security"
           }
           
           $CSE_Logs = $session_log | Where-Object {$_ -match "$CSE" }

           # only process CSE with more than 1 lines of entries
           if ($CSE_Logs.count -gt 1) {

               for($i=0; $i -lt $CSE_Logs.count; $i++) {
                    if ($CSE_Logs[$i] -match "$cse_matching_str") {
                        $CSE_start_time = $CSE_Logs[$i].Split("")[1]
                        break
                    }
               }

               $CSE_end_time = $CSE_Logs[-1].Split("")[1]
               $CSE_total_time = ([datetime]::ParseExact($CSE_end_time, $format,$null)).subtract([datetime]::ParseExact($CSE_start_time, $format,$null)).totalseconds

               
               $list_of_polices = find-policies -array $session_log -String $CSE.trim() -string2 $string2

               # process CSE with at least 1 policy or process time longer than 50ms
               if (($list_of_polices.count -gt 1) -or ($CSE_total_time -gt $min_process_time) ) {

                  write-host "Name of CSE :: second: " $CSE " :: " $CSE_total_time -ForegroundColor Green
              
                   Write-Host "Policies proccessed by the CSE: " -ForegroundColor Yellow
               
                   $list_of_polices |ForEach-Object { write-host "--" $_}
           
                   write-host
                   write-host
                }
                    
           }
           
    }
 
}