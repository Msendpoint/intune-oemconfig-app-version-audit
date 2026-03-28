<#
.SYNOPSIS
    Audits OEMConfig app versions across managed Android Enterprise devices in Microsoft Intune.

.DESCRIPTION
    This script connects to the Microsoft Graph API to enumerate all managed Android Enterprise
    devices and report the installed version of a specified OEMConfig application (e.g., Zebra
    OEMConfig). It is designed to help administrators identify schema version mismatches between
    the OEMConfig app installed on devices and the managed configuration profiles deployed via
    Intune.

    In OEMConfig deployments, the managed configuration schema is embedded inside the OEMConfig
    app itself. If devices run an older app version than what a configuration profile was built
    against, settings may silently fail to apply. This script surfaces those discrepancies at
    scale so remediation can be targeted and efficient.

    Prerequisites:
    - A valid Azure AD access token with the 'DeviceManagementApps.Read.All' Graph API permission.
    - The token can be obtained via MSAL, az cli, or an interactive Connect-MgGraph flow.
    - Update the $Token and $AppDisplayName / $AppPackageName variables before running.

.NOTES
    Author:      Souhaiel Morhag
    Company:     MSEndpoint.com
    Blog:        https://msendpoint.com
    Academy:     https://app.msendpoint.com/academy
    LinkedIn:    https://linkedin.com/in/souhaiel-morhag
    GitHub:      https://github.com/Msendpoint
    License:     MIT

.EXAMPLE
    # Run with a pre-acquired bearer token targeting Zebra OEMConfig
    $Token = 'eyJ0eXAiOiJKV1Q...'  # Replace with a valid access token
    .\Get-OEMConfigAppVersionAudit.ps1 -Token $Token -AppDisplayName 'Zebra OEMConfig' -AppPackageName 'com.zebra.oemconfig.common'

.EXAMPLE
    # Pipe output to a CSV for fleet reporting
    .\Get-OEMConfigAppVersionAudit.ps1 -Token $Token | Export-Csv -Path '.\OEMConfig_VersionAudit.csv' -NoTypeInformation
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'A valid Microsoft Graph API bearer token.')]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [Parameter(Mandatory = $false, HelpMessage = 'Display name of the OEMConfig app as it appears in Intune detected apps.')]
    [string]$AppDisplayName = 'Zebra OEMConfig',

    [Parameter(Mandatory = $false, HelpMessage = 'Android package name of the OEMConfig app.')]
    [string]$AppPackageName = 'com.zebra.oemconfig.common',

    [Parameter(Mandatory = $false, HelpMessage = 'Output format: Table (default) or GridView.')]
    [ValidateSet('Table', 'GridView', 'PassThru')]
    [string]$OutputFormat = 'Table'
)

begin {
    Write-Verbose "[BEGIN] Starting OEMConfig version audit for app: '$AppDisplayName' ($AppPackageName)"

    # Build the standard authorization header used for all Graph API calls
    $Headers = @{
        Authorization  = "Bearer $Token"
        'Content-Type' = 'application/json'
    }

    # Microsoft Graph base URI
    $GraphBaseUri = 'https://graph.microsoft.com/v1.0'

    # Collected results accumulator
    $AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()
}

process {
    try {
        #region --- Query detected apps matching the OEMConfig display name ---
        # The detectedApps endpoint returns apps seen across managed devices.
        # We expand managedDevices to get per-device detail in a single call.
        $DetectedAppUri = ('{0}/deviceManagement/detectedApps?$filter=displayName eq ''{1}''&$expand=managedDevices' -f
            $GraphBaseUri, $AppDisplayName)

        Write-Verbose "[PROCESS] Querying Graph: $DetectedAppUri"

        $Response = Invoke-RestMethod -Uri $DetectedAppUri -Headers $Headers -Method GET -ErrorAction Stop
        #endregion

        if (-not $Response.value -or $Response.value.Count -eq 0) {
            Write-Warning "No detected app entries found for display name '$AppDisplayName'. Verify the app name matches what appears in Intune > Apps > Detected apps."
            return
        }

        Write-Verbose "[PROCESS] Found $($Response.value.Count) detected app version bucket(s)."

        #region --- Flatten per-version buckets into per-device records ---
        foreach ($DetectedAppEntry in $Response.value) {

            $AppVersion = $DetectedAppEntry.version

            if (-not $DetectedAppEntry.managedDevices -or $DetectedAppEntry.managedDevices.Count -eq 0) {
                Write-Verbose "[PROCESS] App version '$AppVersion' has no associated managed devices. Skipping."
                continue
            }

            foreach ($Device in $DetectedAppEntry.managedDevices) {
                $AuditResults.Add(
                    [PSCustomObject]@{
                        DeviceName   = $Device.deviceName
                        DeviceId     = $Device.id
                        AppVersion   = $AppVersion
                        PackageName  = $AppPackageName
                        OSVersion    = $Device.osVersion
                        Manufacturer = $Device.manufacturer
                        Model        = $Device.model
                        EnrollmentDate = if ($Device.enrolledDateTime) { [datetime]$Device.enrolledDateTime } else { $null }
                    }
                )
            }
        }
        #endregion

        #region --- Handle Graph paging (OData nextLink) ---
        # The initial query may return a nextLink if there are more pages of results.
        $NextLink = $Response.'@odata.nextLink'
        while ($NextLink) {
            Write-Verbose "[PROCESS] Following OData nextLink for additional pages..."
            try {
                $PageResponse = Invoke-RestMethod -Uri $NextLink -Headers $Headers -Method GET -ErrorAction Stop
                foreach ($DetectedAppEntry in $PageResponse.value) {
                    $AppVersion = $DetectedAppEntry.version
                    foreach ($Device in $DetectedAppEntry.managedDevices) {
                        $AuditResults.Add(
                            [PSCustomObject]@{
                                DeviceName     = $Device.deviceName
                                DeviceId       = $Device.id
                                AppVersion     = $AppVersion
                                PackageName    = $AppPackageName
                                OSVersion      = $Device.osVersion
                                Manufacturer   = $Device.manufacturer
                                Model          = $Device.model
                                EnrollmentDate = if ($Device.enrolledDateTime) { [datetime]$Device.enrolledDateTime } else { $null }
                            }
                        )
                    }
                }
                $NextLink = $PageResponse.'@odata.nextLink'
            }
            catch {
                Write-Warning "[PROCESS] Failed to retrieve a subsequent page: $_"
                $NextLink = $null
            }
        }
        #endregion
    }
    catch {
        Write-Error "[PROCESS] Failed to query Microsoft Graph for detected apps. Details: $_"
        return
    }
}

end {
    if ($AuditResults.Count -eq 0) {
        Write-Warning "[END] No device records were collected. Check token permissions (DeviceManagementApps.Read.All) and the app display name."
        return
    }

    # Sort results by AppVersion ascending to make version gaps immediately visible
    $SortedResults = $AuditResults | Sort-Object AppVersion, DeviceName

    Write-Verbose "[END] Audit complete. Total devices found: $($SortedResults.Count)"

    # Summarize version distribution for quick analysis
    Write-Host "`n=== OEMConfig App Version Distribution ==="  -ForegroundColor Cyan
    $SortedResults | Group-Object AppVersion | Sort-Object Name | ForEach-Object {
        Write-Host ("  Version {0,-15} : {1,4} device(s)" -f $_.Name, $_.Count) -ForegroundColor White
    }
    Write-Host ''

    switch ($OutputFormat) {
        'Table' {
            $SortedResults | Format-Table -AutoSize -Property DeviceName, Manufacturer, Model, AppVersion, OSVersion, EnrollmentDate
        }
        'GridView' {
            # Requires Windows PowerShell or PowerShell 7 with Out-GridView available
            $SortedResults | Out-GridView -Title "OEMConfig Version Audit - $AppDisplayName"
        }
        'PassThru' {
            # Return objects to the pipeline for further processing (e.g., Export-Csv)
            $SortedResults
        }
    }
}
