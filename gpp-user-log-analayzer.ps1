##########################################################################
#       Script to parse GPPREfer User logs Debugging enable              #
# It's only to analyze processing of User policy, and NOT Machine policy #
# It's only for testing purpose and not for production use               #
##########################################################################
#                                                                        # 
# The input file need to be in ANSI format                               #
# GPPRef user logs need manually open the file in notepad and save using # 
# ANSI encoding; script is meant to be run in Powershell_ISE             #
########################################################################## 
<#     
Author: Ken Mei

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

How to capture GPPRef log? By running Tss tool while repo the login
.\TSS.ps1 -Scenario ADS_GPOEx -ADS_GPedit -ADS_GPmgmt -ADS_GPO -ADS_GPsvc -GPresult Both
https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-tss/gather-information-using-tss-group-policy
Or set it up manually
https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
-----------------------------------------------------------------------------#>


#The input file need to be in ANSI format  

$GPPLogs = Get-Content -path "c:\sample-path-of-GPPREF_User.log"



$string1 = "Entering Process"
$string2 = "----- Changed"
$string3 = "GPO Display Name"
$string4 = "GPO pre-processing"
$String5 = "GPO post-processing"
$usernamestr = "%LogonUser%"
$domainstr = "%LogonDomain%"
$format = "HH:mm:ss:fff"


#Function to determine time of event
Function get-event-time {
    param(
      [string]$line
      )
   
   return ($line.Split("")[1]).Split(".") -join ":"

}
#Function to find start and end index number
Function get-inner-outer-index {
      param(
      [array]$array,
      [string]$startLine,
      [string]$endLine
      )

      for($idx=0; $idx -lt $array.length; $idx++) {
        if ($array[$idx] -match [regex]::Escape("$startLine")) {
           $startIndex = $idx
        }

        if ($array[$idx] -match [regex]::Escape("$endLine")){
            $EndIndex = $idx

            return "$startIndex,$EndIndex"
        }
     }
}

#Function to find all logs for each CSE processing
Function get-cselogs  {
    param(
      [array]$array,
      [string]$startIndex,
      [string]$endIndex
      )

      $intStartIndex = [int]$startIndex
      $intendIndex = [int]$endIndex
    # now we use the readcount property which is an int to loop through all the lines between and add to an array - $array
        $arraylogs = @()
        for ($i = $intstartIndex; $i -lt ($intendIndex + 1); $i++)
        {
        $arraylogs += $array[$i]
        }
        # $array now contains all lines between your start and end points!

    return $arraylogs

}

#Function to find the policies if avaiable being processed by each CSE
function find-policies {
  param(
  [array]$array,
  [string]$String,
  [string]$string1,
  [string]$string2
  )
 
 $objectcollection =@()

   foreach ($line in $array) {

      if ($line -match [regex]::Escape($string4)){
          $startime = get-event-time -line $line
      }

      if ($line -match [regex]::Escape($string3)){
          $policy = ($line -split('Name \:'))[1].trim()
      }

      if ($line -match [regex]::Escape($string5)){
          $endtime = get-event-time -line $line
          $total_time = ([datetime]::ParseExact($endtime, $format,$null)).subtract([datetime]::ParseExact($startime, $format,$null)).totalseconds
      
          # Create a new object
          $obj = New-Object PSObject -Property @{
            Starttime = $startime
            Endtime = $endtime
            policy = $policy
            totaltime = $total_time
            }
    
          $objectcollection += $obj
      }
   }

  return $objectcollection
  
}  #end of find index function

#get the different pid/tid, each represent a different sessioin
$sessions = ($GPPLogs | Where-Object {$_ -match "$string1"} | ForEach-Object { ($_.split(" ")[2])} |Select-Object -Unique)


$collectionEvents = @()

foreach ($session in $sessions) {

     
   # get the Pid/Tid from HEX to Decimal
   $hPID = $session.Split(',')[0].Split("\=")[1]
   $hTID = $session.Split(',')[1].Split("\=")[1].split("]")[0]
   $dPid = [System.Convert]::ToInt32($hPID,16)
   $dTid = [System.Convert]::ToInt32($hTID,16)

   # get logs for each unique session, and total duration of the session
   $session_log = $GPPLogs |Where-Object {$_ -match [regex]::escape($session)}
   $starttime = get-event-time -line $session_log[0]
   $endtime = get-event-time -line $session_log[-1]
   $total_time = ([datetime]::ParseExact($endtime, $format,$null)).subtract([datetime]::ParseExact($starttime, $format,$null)).totalseconds

 
   # determine how many CES was processed
   $total_CSE = $session_log | Where-Object { $_ -match "$string1"} | ForEach-Object { ($_ -split (" "))[-1].Split("(")[0]}

   #determine each user user if avaiable 
   $usernameline = ($session_log  | Where-Object {$_ -match [regex]::Escape("$usernamestr")}).Split("")[-1] | select -Unique
   if ($usernameline -eq $null) { 
        $username = "No UserName Captured"
   } else {
        $username = $usernameline.Trim('""')
   }
   # determine each domain if avaiable 
    $domainline = ($session_log  | Where-Object {$_ -match [regex]::Escape("$domainstr")}).Split("")[-1] | select -Unique
   if ($domainline -eq $null) { 
        $domainname = "No Domain Name Captured"
   } else {
        $domainname= $domainline.Trim('""')
   }

   
   $collectCSE = @()
   foreach ($CSE in $total_CSE) {
                     
           $startcsestr = "Entering $CSE"
           $endcsestr = "Leaving $CSE"
           
           $entercseline = $session_log | Where-Object { $_ -match [regex]::Escape("$startcsestr")}
           $endcseline = $session_log | Where-Object { $_ -match [regex]::Escape("$endcsestr")}

           $cse_starttime = get-event-time -line $entercseline
           $cse_endtime = get-event-time -line $endcseline
           $cse_processed_time = ([datetime]::ParseExact($cse_endtime, $format,$null)).subtract([datetime]::ParseExact($cse_starttime, $format,$null)).totalseconds

           $start_end_cse_indexs = get-inner-outer-index -array $session_log -startLine $entercseline -endLine $endcseline

           $cse_logs = get-cselogs -array $session_log -startIndex $start_end_cse_indexs.Split(",")[0] -endIndex $start_end_cse_indexs.Split(",")[1]

           $Policies = find-policies -array $cse_logs -String $string2 -string1 $string3 -string2 $String5
    
           # Create a new object
                  $cseobj = New-Object PSObject -Property @{
                    cseName = $CSE
                    cseStartTime =  $cse_starttime
                    cseEndTime = $cse_endtime
                    cseTotalTime = $cse_processed_time
                    csePolicies  =  $Policies
                    }
            $collectCSE += $cseobj

    }


     # Create a new object
          $obj = New-Object PSObject -Property @{
            HPID = $hPID
            HTID = $hTID
            DPID = $dPid
            DTID = $dTid
            sStartTime = $starttime
            SEndTime = $endtime
            tTotalTime = $total_time
            sUsername = $username
            sDomain = $domainname
            totaltime = $total_time
            colCES = $collectCSE
            }
 
      $collectionEvents += $obj
}

 foreach ($evt in  $collectionEvents){
     write-host "***************************************************************************"
     write-host "****************************************************************************"
     write-host "****************************************************************************"
     write-host "This is session: " $evt.HPID":"$evt.HTID " or in Decimal " $evt.DPID":"$evt.DTID -ForegroundColor Magenta
     Write-host "->UserName" $evt.sUsername  "in Domain" $evt.sDomain
     write-host "-->Start time: " $evt.sStartTime
     write-host "-->End Time: " $evt.sEndTime
     write-host "-->Total Duratin for session in Second: " $evt.tTotalTime
     write-host "--------------------------------"
     foreach ($cse in $evt.colCES) {

         write-host "------> Client-Side Extension Name: " $cse.cseName -ForegroundColor Green
         write-host "-------> Start Time: " $cse.cseStartTime
         write-host "-------> End Time: " $cse.cseEndTime
         write-host "-------> Total Duration in Seconds: " $cse.cseTotalTime
         write-host "----------->Policy being process: "
         foreach ($policy in $cse.csePolicies) {

            write-host "              " $policy.policy -ForegroundColor yellow
            write-host "                  Start Time: " $policy.Starttime
            write-host "                  End Time: " $policy.Endtime
            write-host "                  Total Duration in Second: " $policy.totaltime
           
         }

     }
}
