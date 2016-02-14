# Copyright © 2008, Microsoft Corporation. All rights reserved.

#include utility functions and localization data
. .\UtilityFunctions.ps1
Import-LocalizedData -BindingVariable localizationString -FileName LocalizationData

#set the environment constants
.\UtilitySetConstants

Write-DiagProgress -activity $localizationString.progress_Diagnosing_Initializing

#reset the global NDF object
$Global:ndf = $null
$Global:previousNdf = $null

#initialize script level variables (script scope used to avoid odd powershell scope handling)
$script:ExpectingException = $false
$script:incidentID = $null
$Global:incidentData = $null #need to access this during verification as well
$script:skipRerun = $false
$script:attachTraceFile = $false
$script:isRerun = $false

#first check whether we're either elevated or a re-run scenario
&{
    $prevIncidentID = 0
    $prevFlags = 0

    $script:ExpectingException = $true
    #marked as no-ui. throws exception if not available
    $SBSData = Get-DiagInput -ID "SecurityBoundarySafe"
    $script:ExpectingException = $false

    if($SBSData[0].Length -gt 0)
    {
        #Security boundary safe data is now always passed in to our script on rerun or elevation
        #We use the "flags" field to determine whether it's a rerun or elevation  -- if the flag doesn't match the current privilege, we elevated
        "SBS Data Retrieved: " + $SBSData  | convertto-xml | Update-DiagReport -id SecurityBoundarySafe -name "Security Boundary Safe" -verbosity Debug

        $script:isRerun = $true
        $admin = IsAdmin
        SplitSBSData $SBSData[0] ([ref]$prevIncidentID) ([ref]$prevFlags)
        if([System.Int32]($prevFlags) -eq [System.Int32]($admin))
        {
            "Previous run's privilege level flag (" + $prevFlags + ") matches our current level (IsAdmin:" + $admin +"). Determining whether it's appropriate to re-run." | convertto-xml | Update-DiagReport -id ReuseSession -name "Reusing previous session" -verbosity Debug

            #same privilege level as last run, so this is a rerun rather than elevation
            #should not use previous incident, but should determine whether rerun is necessary

            #open the previous incident
            $Global:ndf = GetExistingNDFInstance $prevIncidentID
            if($Global:ndf)
            {
                #recover the input attributes so we don't re-prompt
                $prevHelperClass = $Global:ndf.EntryPoint
                $prevHelperAttributes = $Global:ndf.HelperAttributes
                $Global: