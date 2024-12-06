##########################################################################
#  Script to analyze Microsoft-Windows-GroupPolicy-Operational eventlog  #
# It's to analyze processing of User policy, or  Machine policy          #
# It's only for testing purpose and not for production use               #
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
 

HOw-to:

This is to analaze GPP client-side extension processing base on eventlogs
how to eport the eventlogs

wevtutil.exe export-log Microsoft-Windows-GroupPolicy/Operational %Temp%\GroupPolicy.evtx /overwrite:true

-------
https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance#determine-the-instance-of-group-policy-processing

#>

#Run directly on the server you want to invetigate
$choice = Read-Host "Please enter COMPUTER OR USER to proceed"

#Function to find Events
Function find-events {
  param(
    [array]$array,
    [string]$evtID
  )

  $evt = $array | Where-Object {$_.id -match "$evtID"}

  return $evt
}

Function get-user-policy-data{
    param(
      [string]$logname = "Microsoft-Windows-GroupPolicy/Operational",
      [int]$maxEvt = 2000
    )

    $activityList = @()
    $evtID4001 = "4001"
    $evtID5017 = "5017"
    $evtID4016 = "4016"
    $evtID5016 = "5016"
    $evtID5326 = "5326"
    $evtID8001 = "8001"
    $evtID5117 = "5117"
    $evtID5126 = "5126"


    $activityIDs = Get-WinEvent -LogName $Logname  -MaxEvents $maxEvt |Where-Object {$_.id -match $evtID4001}| ForEach-Object {$_.ActivityId.Guid} | select -Unique
   
    $ErrorSessions = @()
    $collsessions = @()
    foreach ($activitID in $activityIDs) {

         $query = ("<QueryList><Query Id=""0"" Path=""$logname""><Select Path=""$logname"">*[System/Correlation/@ActivityID='{$activitID}']</Select></Query></QueryList>")
         $events=Get-WinEvent -LogName $Logname -FilterXPath $query  -Oldest

         if ($events.LevelDisplayName -contains "error") {
            $eventerrors = $events | where-Object { $_.LevelDisplayName -eq "Error"}
            # Create a new object
             $errobj = New-Object PSObject -Property @{
                            error_time = $events[0].TimeCreated
                            activityID = $activitID
            }
            $ErrorSessions += $errobj
     
         } else{
             $evt4001 = find-events -array $events -evtID $evtID4001
             $evt8001 = find-events -array $events -evtID $evtID8001
             $evt4016 = find-events -array $events -evtID $evtID4016
             $evt5016 = find-events -array $events -evtID $evtID5016
             $evt5017 = find-events -array $events -evtID $evtID5017
             $evt5117 = find-events -array $events -evtID $evtID5117
             $evt5126 = find-events -array $events -evtID $evtID5126
          
             $evtxml4001 = New-Object -TypeName System.Xml.XmlDocument
             $evtxml4001 = ([Xml]($evt4001.ToXml())).event
     
             $evtxml8001 = New-Object -TypeName System.Xml.XmlDocument
             $evtxml8001 = ([Xml]($evt8001.ToXml())).event

             $evtxml5126 = New-Object -TypeName System.Xml.XmlDocument
             $evtxml5126 = $evt5126 | ForEach-Object { ([xml]$_.toxml()).event}

             $evtxml5117 = New-Object -TypeName System.Xml.XmlDocument
             $evtxml5117 = ([Xml]($evt5117.ToXml())).event

             $evtxml5016 = New-Object -TypeName System.Xml.XmlDocument
             $evtxml5016 = $evt5016 | ForEach-Object { ([xml]$_.toxml()).event}

             $evtxml4016 = New-Object -TypeName System.Xml.XmlDocument
             $evtxml4016 = $evt4016 | ForEach-Object { ([xml]$_.toxml()).event}
     
             $collcesobj = @()
             for($i=0; $i -lt $evtxml5016.count ; $i++) {
        
                 $CSE = $evtxml5016[$i].EventData.Data[2].'#text'
                 $CSE_duration = $evtxml5016[$i].EventData.Data[0].'#text'
                 $policy_in_CSE = ($evtxml4016[$i].EventData.Data[5].'#text').Split([Environment]::NewLine)
                # Create a new object
                  $cseobj = New-Object PSObject -Property @{
                            cseName = $CSE
                            cseTotalTime = $CSE_duration
                            csePolicies =  $policy_in_CSE
                            }

                  $collcesobj += $cseobj
              }
    
      
              # Create a new object
              $sessionObj = New-Object PSObject -Property @{
                            Username = $evtxml4001.EventData.Data[1].'#text'  
                            pid = $evtxml4001.System.Execution.ProcessID
                            tid = $evtxml4001.System.Execution.ThreadID
                            sessionstart = $evt4001.TimeCreated
                            sessionend = $evt5117.TimeCreated
                            SessionDuration = $evtxml5117.EventData.data[1].'#text'
                            PolicyElaspedTimeInSeconds = $evtxml8001.EventData.data[0].'#text'
                            GPODownloadTimeInMilliseconds = $evtxml5126.EventData.data[5].'#text'
                            CSE = $collcesobj
                            }                 
             $collsessions += $sessionObj

         }

}

    foreach ($evt in  $collsessions){
         write-host "***************************************************************************"
         write-host "****************************************************************************"
         write-host "****************************************************************************"
         write-host "This is session: " $evt.PID":"$evt.TID -ForegroundColor Magenta
         write-host "session start: " $evt.Sessionstart
         write-host "session end: " $evt.Sessionend
         Write-host "->UserName" $evt.Username 
         write-host "-->Total Duration for session in Second: "  ($evt.SessionDuration/1000)
         Write-host "---->Total Time to download all policies in Second: " ($evt.GPODownloadTimeInMilliseconds/1000)
         write-host "--------------------------------"
         foreach ($cse in $evt.CSE) {

             write-host "------> Client-Side Extension Name: " $cse.cseName -ForegroundColor Green
             write-host "-------> Total Duration in milliseconds: " $cse.cseTotalTime
             write-host "----------->Policy being process: " 
             foreach ($policy in $cse.csePolicies) {
                write-host "               " $policy -ForegroundColor yellow
            
             }

          }
}
    if ($ErrorSessions -ne $null) {
       write-host "******************************" -ForegroundColor Red
       write-host "******************************" -ForegroundColor Red

       foreach ($session in $ErrorSessions){  
       write-host "Below session has error, please examine manual by creating a custom view in eventlog"
       write-host "  date/time: "$session.error_time
       Write-Host "  session activity id: " $session.activityID
       write-host "  xml filter: " ("<QueryList><Query Id=""0"" Path=""file://$Logname""><Select Path=""file://$Logname"">*[System/Correlation/@ActivityID='{$session}']</Select></Query></QueryList>") -ForegroundColor Magenta
    }
}
}

Function get-computer-policy-data {
    param(
       [string]$Logname="Microsoft-Windows-GroupPolicy/Operational",
       [int]$maxEvt = 2000
    )
    
    $activityList = @()
    $evtID4000 = "4000" #start session
    $evtID5017 = "5017"
    $evtID4016 = "4016" #start cse
    $evtID5016 = "5016" #complete cse
    $evtID7016 = "7016" #complete cse with error
    $evtID5326 = "5326" #discover policy
    $evtID5257 = "5257" #download plicies
    $evtID8000 = "8000" #complete boot policy processing
    $evtID5117 = "5117" #complete the whole session
    $evtID5126 = "5126" #download plicies
    $evtID4018 = "4018" #startup script
    $evtID5018 = "5018" #end of Startup SCript

       
    $activityIDs = Get-WinEvent -LogName $Logname  -MaxEvents $maxEvt |Where-Object {$_.id -match $evtID4000}| ForEach-Object {$_.ActivityId.Guid} | select -Unique

    $ErrorSessions = @()
    $collsessions = @()

                                                                                                                                                                                                                                                                                                                                                    if ($activityIDs -ne $null){
    foreach ($activitID in $activityIDs) {

        $query = ("<QueryList><Query Id=""0"" Path=""$Logname""><Select Path=""$Logname"">*[System/Correlation/@ActivityID='{$activitID}']</Select></Query></QueryList>")
        $events=Get-WinEvent -LogName $Logname -FilterXPath $query  -Oldest
     
        if ($events.LevelDisplayName -contains "error") {
            $eventerrors = $events | where-Object { $_.LevelDisplayName -eq "Error"}
             # Create a new object
             $errobj = New-Object PSObject -Property @{
                            error_time = $events[0].TimeCreated
                            activityID = $activitID
            }
            $ErrorSessions += $errobj
     
         } else{


         if ($events.id -contains "$evtID4018") {
        
            $starucript = "true"
         } else {
            $starucript = "false"
         }
     
         write-host $activityID
    
         $evt4000 = find-events -array $events -evtID $evtID4000
         $evt8000 = find-events -array $events -evtID $evtID8000
         $evt4016 = find-events -array $events -evtID $evtID4016
         $evt5016 = find-events -array $events -evtID $evtID5016
         $evt5017 = find-events -array $events -evtID $evtID5017
         $evt5117 = find-events -array $events -evtID $evtID5117
         $evt5126 = find-events -array $events -evtID $evtID5126
         $evt4018 = find-events -array $events -evtID $evtID4018
         $evt5018 = find-events -array $events -evtID $evtID5018
          
         $evtxml4000 = New-Object -TypeName System.Xml.XmlDocument
         $evtxml4000 = ([Xml]($evt4000.ToXml())).event
     
         $evtxml8000 = New-Object -TypeName System.Xml.XmlDocument
         $evtxml8000 = ([Xml]($evt8000.ToXml())).event

         $evtxml5126 = New-Object -TypeName System.Xml.XmlDocument
         $evtxml5126 = $evt5126 | ForEach-Object { ([xml]$_.toxml()).event}

         $evtxml5117 = New-Object -TypeName System.Xml.XmlDocument
         $evtxml5117 = ([Xml]($evt5117.ToXml())).event

     
         $starupscript_duration = $null
         if ($evt5018 -ne $null) {
                $evtxml4018 = New-Object -TypeName System.Xml.XmlDocument
                $evtxml4018 = $evt4018 | ForEach-Object { ([xml]$_.toxml()).event}
                $evtxml5018 = New-Object -TypeName System.Xml.XmlDocument
                $evtxml5018 = ([Xml]($evt5018.ToXml())).event
                $starupscript_duration = $evtxml5018.EventData.data[0].'#text'
         } 

         $evtxml5016 = New-Object -TypeName System.Xml.XmlDocument
         $evtxml5016 = $evt5016 | ForEach-Object { ([xml]$_.toxml()).event}

         $evtxml4016 = New-Object -TypeName System.Xml.XmlDocument
         $evtxml4016 = $evt4016 | ForEach-Object { ([xml]$_.toxml()).event}
     
         $collcesobj = @()
         for($i=0; $i -lt $evtxml5016.count ; $i++) {
        
             $CSE = $evtxml5016[$i].EventData.Data[2].'#text'
             $CSE_duration = $evtxml5016[$i].EventData.Data[0].'#text'
             $policy_in_CSE = ($evtxml4016[$i].EventData.Data[5].'#text').Split([Environment]::NewLine)
            # Create a new object
              $cseobj = New-Object PSObject -Property @{
                        cseName = $CSE
                        cseTotalTime = $CSE_duration
                        csePolicies =  $policy_in_CSE
                        }

              $collcesobj += $cseobj
          }
    
      
          # Create a new object
          $sessionObj = New-Object PSObject -Property @{
                        Username = $evtxml4000.EventData.Data[1].'#text'  
                        pid = $evtxml4000.System.Execution.ProcessID
                        tid = $evtxml4000.System.Execution.ThreadID
                        sessionstart = $evt4000.TimeCreated
                        sessionend = $evt5117.TimeCreated
                        SessionDuration = $evtxml5117.EventData.data[1].'#text'
                        PolicyElaspedTimeInSeconds = $evtxml8000.EventData.data[0].'#text'
                        GPODownloadTimeInMilliseconds = $evtxml5126.EventData.data[5].'#text'
                        ScriptElaspedTimeInSeconds = $starupscript_duration
                        CSE = $collcesobj
                        }                 
         $collsessions += $sessionObj

    }
    }
    } else{  write-host "No Activity found"
        }


    foreach ($evt in  $collsessions){
     write-host "***************************************************************************"
     write-host "****************************************************************************"
     write-host "****************************************************************************"
     write-host "This is session: " $evt.PID":"$evt.TID -ForegroundColor Magenta
     write-host "session start: " $evt.Sessionstart
     write-host "session end: " $evt.Sessionend
     Write-host "->UserName" $evt.Username 
     write-host "-->Total Duration for session in Second: "  ($evt.SessionDuration /1000)
     write-host "--------->Boot policy processing time in second: " ($evt.PolicyElaspedTimeInSeconds)
     if ($starupscript_duration -ne $null) {   
     write-host "--------->Startup Script processing time in second: " ($evt.ScriptElaspedTimeInSeconds)
     }
     Write-host "---->Total Time to download all policies in Second: " ($evt.GPODownloadTimeInMilliseconds/1000)
     write-host "--------------------------------"
     foreach ($cse in $evt.CSE) {

         write-host "------> Client-Side Extension Name: " $cse.cseName -ForegroundColor Green
         write-host "-------> Total Duration in milliseconds: " $cse.cseTotalTime
         write-host "----------->Policy being process: " 
         foreach ($policy in $cse.csePolicies) {
            write-host "               " $policy -ForegroundColor yellow
            
         }

      }
}

    if ($ErrorSessions -ne $null) {
       write-host "******************************" -ForegroundColor Red
       write-host "******************************" -ForegroundColor Red

       foreach ($session in $ErrorSessions){  
           write-host "Below session has error, please examine manual by creating a custom view in eventlog"
           write-host "  date/time: "$session.error_time
           Write-Host "  session activity id: " $session.activityID
           write-host "xml filter: " ("<QueryList><Query Id=""0"" Path=""file://$Logname""><Select Path=""file://$Logname"">*[System/Correlation/@ActivityID='{$session}']</Select></Query></QueryList>") -ForegroundColor Magenta
        }
    }
}

switch ($choice) {
  "computer" {get-computer-policy-data}
  "user" {get-user-policy-data}
  default {get-user-policy-data}
    
}