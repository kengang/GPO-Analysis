##########################################################################
#  Script to analyze Microsoft-Windows-GroupPolicy-Operational eventlog  #
# It's only to analyze processing of User policy, and NOT Machine policy #
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

param (
  [string]$Path,
  [int]$MaxEvents = 200 # look at latest 1000 events only
)


$max = $MaxEvents # look at latest 1000 events only
$activityList = @()
$evtID4001 = "4001"
$evtID5017 = "5017"
$evtID4016 = "4016"
$evtID5016 = "5016"
$evtID5326 = "5326"
$evtID8001 = "8001"
$evtID5117 = "5117"
$evtID5126 = "5126"


#Function to find Events
Function find-events {
  param(
    [array]$array,
    [string]$evtID
  )

  $evt = $array | Where-Object {$_.id -match "$evtID"}

  return $evt
}



if (-not $path) {
     Write-Host "Please specify a file name" -ForegroundColor red
       
} else{

     if (!(Get-Item -path $path -ErrorAction SilentlyContinue)) {
          Write-Host "Input file does not exist, please put in the correct path" -ForegroundColor Red
     } else {

        $query = ("<QueryList><Query Id=""0"" Path=""file://$Path""><Select Path=""file://$path"">*[System/Correlation/@ActivityID='{$activitID}']</Select></Query></QueryList>")

        $activityIDs = Get-WinEvent -Path $path -MaxEvents $max |Where-Object {$_.id -match $evtID4001}| ForEach-Object {$_.ActivityId.Guid} | select -Unique


        $collsessions = @()
        foreach ($activitID in $activityIDs) {

     $query = ("<QueryList><Query Id=""0"" Path=""file://$Path""><Select Path=""file://$path"">*[System/Correlation/@ActivityID='{$activitID}']</Select></Query></QueryList>")
     $events=Get-WinEvent -Path $Path -FilterXPath $query  -Oldest
       
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
                    SessionDuration = $evtxml5117.EventData.data[1].'#text'
                    PolicyElaspedTimeInSeconds = $evtxml8001.EventData.data[0].'#text'
                    GPODownloadTimeInMilliseconds = $evtxml5126.EventData.data[5].'#text'
                    CSE = $collcesobj
                    }                 
     $collsessions += $sessionObj

}

 }
}
foreach ($evt in  $collsessions){
     write-host "***************************************************************************"
     write-host "****************************************************************************"
     write-host "****************************************************************************"
     write-host "This is session: " $evt.PID":"$evt.TID -ForegroundColor Magenta
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