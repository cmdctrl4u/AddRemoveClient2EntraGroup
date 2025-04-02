<# 

Origin author: Matthias Langenhoff
URL: https://cmdctrl4u.wordpress.com
GitHub: https://github.com/cmdctrl4u
Date: 2025-31-03
Version: 1.0

Description: This PowerShell script checks the membership of devices in a specific Azure AD group based on installed software (or anything else you want to check).

It performs the following tasks:

Authentication via Microsoft Graph API – Retrieves an access token for Azure AD access.

Retrieve Device Information – Obtains the device ID and its corresponding object ID in Azure AD.

Software Detection – Checks whether specific software (e.g., Adobe Photoshop, New Outlook, Firefox) is installed on the device.

Manage Azure AD Group Membership –

If the software is installed, the device is added to the corresponding Azure AD group.

If the software is not installed, the device is removed from the group.

The script uses the Microsoft Graph PowerShell SDK to query the Microsoft Graph API.
The script is based on the following Microsoft Graph API documentation: https://docs.microsoft.com/en-us/graph/api/resources/intune-devices-devicemanagementdevicehealthscript?view=graph-rest-beta

#>



# Define path to logfile
$logFilePath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\FlenderGmbH_UpdateAzureGroupDynamically.log"

# Start logging script execution 
Start-Transcript -Path $logFilePath -Force

# Function to retrieve an Azure AD Access Token
function Get-AzureADAccessToken {
    param (
        [string]$Tenant,       # Azure AD Tenant ID
        [string]$ClientId,     # Application ID for registered app in Azure AD
        [string]$ClientSecret  # Client Secret for authentication
    )

    $headers = @{
        "Content-Type" = "application/x-www-form-urlencoded"
    }

    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
    }

    try {
        # Request an access token from Microsoft Graph API
        $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Method POST -Headers $headers -Body $body
        return $response.access_token
    } catch {
        Write-Host "Error retrieving access token: $_" -ForegroundColor Red
        exit 1
    }
}

# Function to check if a specific software is installed on the machine
function Get-InstalledSoftware {
    param (
        [string]$Softwarename  # The name of the software to check for
    )

    try {
        # Query registry for installed software
        $key = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ItemProperty | Where-Object { $_.DisplayName -match $Softwarename }
        return $key
    } catch {
        Write-Host "Error checking installed software: $_" -ForegroundColor Red
        return $null
    }
}

# Function to check if New Outlook is installed
function Check-NewOutlookInstallation {
    $outlookPackage = Get-AppxPackage Microsoft.OutlookForWindows -ErrorAction SilentlyContinue
    return $outlookPackage -ne $null
}

# Function to check if Firefox is installed in the user context
function Check-FirefoxUserInstallation {
    $userProfiles = Get-ChildItem "C:\Users" -Directory
    foreach ($profile in $userProfiles) {
        $firefoxPath = "C:\Users\$($profile.Name)\AppData\Local\Mozilla Firefox"
        if (Test-Path "$firefoxPath\firefox.exe") {
            Write-Host "Firefox found in user profile: $($profile.Name)"
            return $true
        }
    }
    
}

# Function to get the device ID using dsregcmd
function Get-DeviceId {
    $RegStatus = dsregcmd /status
    if ($RegStatus -match "DeviceId") {
        return ($RegStatus -match "DeviceId").Split(":")[1].Trim()
    } else {
        Write-Host "No device Id Found" -ForegroundColor Red
        exit 1
    }
}

# Function to retrieve the device object ID from Azure AD
function Get-DeviceObjectId {
    param (
        [string]$DeviceId,
        [string]$AccessToken
    )

    $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($DeviceId)'&`$select=id"
    try {
        $DeviceObjId = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
        if ($DeviceObjId.value.Count -eq 0) {
            Write-Host "No device found with the specified DeviceId." -ForegroundColor Red
            exit 1
        }
        return $DeviceObjId.value[0].id
    } catch {
        Write-Host "Error retrieving device object ID: $_" -ForegroundColor Red
        exit 1
    }
}

# Function to check if the device is a member of a group
function Check-DeviceInGroup {
    param (
        [string]$DeviceId,
        [string]$GroupID,
        [string]$AccessToken
    )

    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupID/members"
    $members = @()

    do {
        try {
            $response = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
            $members += $response.value
            $uri = $response.'@odata.nextLink'
        } catch {
            Write-Host "Error retrieving group members: $_" -ForegroundColor Red
            exit 1
        }
    } while ($uri -ne $null)

    return ($members.id -contains $DeviceId)
}

# Function to update Azure device group membership based on software installation
function Execute-UpdateAzureDeviceMembership {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Softwarename,
        [Parameter(Mandatory = $true)]
        [string]$GroupID
    )

    $isInstalled = $false
    $AccessToken = Get-AzureADAccessToken -Tenant "<Tenant-ID>" -ClientId "<Client-ID>" -ClientSecret "<Client-Secret>"
    $DeviceId = Get-DeviceId
    $DeviceObjId = Get-DeviceObjectId -DeviceId $DeviceId -AccessToken $AccessToken
    $BodyContent = @{"@odata.id"="https://graph.microsoft.com/v1.0/devices/$DeviceObjId"} | ConvertTo-Json -Depth 3

    $isInstalled = if ($Softwarename -eq "NewOutlook") {
        Check-NewOutlookInstallation
    } 
    
    elseif ($Softwarename -eq "Firefox") {
        $key = Get-InstalledSoftware -Softwarename $Softwarename
        if ($key -eq $null) {$key = Check-FirefoxUserInstallation}
        $key -ne $null
    }
    
    else{
        $key = Get-InstalledSoftware -Softwarename $Softwarename
        $key -ne $null
    }

    $isInGroup = Check-DeviceInGroup -DeviceId $DeviceObjId -GroupID $GroupID -AccessToken $AccessToken

    if ($isInstalled) {
        if (-not $isInGroup) {
            Write-Host "$Softwarename is installed. Adding device to the group..." -ForegroundColor Green
            try {
                Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$GroupID/members/`$ref" -Headers @{Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json'} -Body $BodyContent
            } catch {
                Write-Host "Error adding device to group: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "$Softwarename is installed and already in the group." -ForegroundColor Green
        }
    } else {
        if ($isInGroup) {
            Write-Host "$Softwarename is not installed. Removing device from the group..." -ForegroundColor Yellow
            try {
                Invoke-RestMethod -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$GroupID/members/$DeviceObjId/`$ref" -Headers @{Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json'}
            } catch {
                Write-Host "Error removing device from group: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "$Softwarename is not installed and not in the group." -ForegroundColor Yellow
        }
    }
}

# Example function calls to update device group membership
Execute-UpdateAzureDeviceMembership -Softwarename "Adobe Photoshop" -GroupID "<GroupID>"
Execute-UpdateAzureDeviceMembership -Softwarename "NewOutlook" -GroupID "<GroupID>"
Execute-UpdateAzureDeviceMembership -Softwarename "Firefox" -GroupID "<GroupID>"

# Stop Transcription
Stop-Transcript

#Exit 0
