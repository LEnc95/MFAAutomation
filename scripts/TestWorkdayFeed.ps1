<#
.SYNOPSIS
  Test script to retrieve and display data from Workday RaaS feed.

.DESCRIPTION
  This script connects to a Workday RaaS feed and retrieves user data,
  displaying the results in a readable format.

.NOTES
  - Uses basic authentication with Workday credentials
  - Outputs data in a formatted table
  - Includes error handling and logging
#>

#=====================
# 1) CONFIG & LOGGING
#=====================

# Paths for logging
$LogDir = "C:\Scripts\Logs"
$LogFile = "$LogDir\TestWorkdayFeed.log"
$DataLogDir = "$LogDir\WorkdayData"

# Create log directories if they don't exist
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
if (!(Test-Path $DataLogDir)) {
    New-Item -ItemType Directory -Path $DataLogDir | Out-Null
}

# Simple helper for writing to host and log
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,
        [string] $Level = "INFO"
    )
    $entry = "{0} - {1}: {2}" -f (Get-Date), $Level, $Message
    Write-Host $entry
    Add-Content -Path $LogFile -Value $entry
}

# Function to log data fetch results
function Write-DataLog {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Data
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dataLogFile = "$DataLogDir\workday_data_$timestamp.xml"
    
    # Save raw XML data
    $Data | Out-File -FilePath $dataLogFile -Encoding UTF8
    
    Write-Log "Data fetch logged to: $dataLogFile"
}

# Function to get secrets from Secret Server
function Get-SecretServerSecretDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$SecretID,
        [Parameter(Mandatory=$false)]
        [string]$SecretServerName = 'creds.gianteagle.com',
        [switch]$TLS12
    )

    if ($TLS12) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    $BaseURL = "https://$SecretServerName/SecretServer/winauthwebservices/api/v1/secrets"
    $Arglist = @{
        Uri = "$BaseURL/$SecretID"
        UseDefaultCredentials = $true  # This enables Windows authentication
        Method = 'GET'
        Headers = @{
            'Accept' = 'application/json'
        }
    }

    Write-Log "Retrieving secret details from Secret Server using Windows authentication..."
    try {
        $SecretDetails = Invoke-RestMethod @Arglist
        Write-Log "Successfully retrieved secret details from Secret Server"
        return $SecretDetails
    }
    catch {
        Write-Log "Failed to retrieve secret details from Secret Server: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

#=====================
# 2) WORKDAY CONFIG
#=====================
# Get Workday credentials from Secret Server
$workdaySecretID = 42989  # Secret ID for Workday credentials
$workdaySecretDetails = Get-SecretServerSecretDetails -SecretID $workdaySecretID -TLS12

$workdayConfig = @{
    Url = ($workdaySecretDetails.items | Where-Object { $_.slug -eq "url" }).itemValue
    Format = "simplexml"
    Username = ($workdaySecretDetails.items | Where-Object { $_.slug -eq "username" }).itemValue
    Password = ($workdaySecretDetails.items | Where-Object { $_.slug -eq "password" }).itemValue
}

#=====================
# 3) WORKDAY DATA RETRIEVAL
#=====================
function Get-WorkdayData {
    param (
        [hashtable] $Config
    )

    $fullUrl = "$($Config.Url)?format=$($Config.Format)"
    Write-Log "Attempting to connect to Workday feed: $fullUrl"

    $cred = New-Object System.Management.Automation.PSCredential(
        $Config.Username, 
        (ConvertTo-SecureString $Config.Password -AsPlainText -Force)
    )

    try {
        Write-Log "Sending request to Workday..."
        $response = Invoke-RestMethod -Uri $fullUrl -Method GET -Credential $cred -ErrorAction Stop
        
        # Debug: Show raw response
        Write-Log "Raw Response:"
        Write-Log $response
        
        Write-Log "Successfully retrieved data from Workday"
        return $response
    }
    catch {
        Write-Log "ERROR retrieving Workday data: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Response Status Code: $($_.Exception.Response.StatusCode.value__)" -Level "ERROR"
        Write-Log "Response Status Description: $($_.Exception.Response.StatusDescription)" -Level "ERROR"
        return $null
    }
}

#=====================
# 4) MAIN FUNCTION
#=====================
function Get-WorkdayMFAUsers {
    Write-Log "Starting Workday feed test..."

    # Get the data
    $workdayData = Get-WorkdayData -Config $workdayConfig

    if ($workdayData) {
        Write-Log "Data retrieved successfully. Displaying results..."
        
        # Log the raw data
        Write-DataLog -Data $workdayData
        
        # Create XML document
        [xml]$xmlDoc = $workdayData
        
        # Add namespace manager
        $nsManager = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $nsManager.AddNamespace("wd", "urn:com.workday/bsvc")
        
        # Debug: Show XML structure
        Write-Host "`nXML Structure:"
        Write-Host "-------------"
        $xmlDoc | Format-List
        
        # Extract data using XPath
        $entries = $xmlDoc.SelectNodes("//wd:Report_Entry", $nsManager)
        
        Write-Host "`nFound $($entries.Count) entries"
        
        # Process entries
        $userData = @()
        foreach ($entry in $entries) {
            Write-Log "Processing entry XML: $($entry.OuterXml)" -Level "DEBUG"
            
            try {
                # Get Team Member ID
                $teamMemberId = $entry.SelectSingleNode("wd:Team_Member_ID", $nsManager).InnerText
                Write-Log "Team Member ID: $teamMemberId" -Level "DEBUG"
                
                # Get UPN
                $upnNode = $entry.SelectSingleNode("wd:UPN", $nsManager)
                $upn = $upnNode.GetAttribute("Descriptor", "urn:com.workday/bsvc")
                Write-Log "UPN: $upn" -Level "DEBUG"
                
                # Get Mobile
                $mobileNode = $entry.SelectSingleNode("wd:Mobile", $nsManager)
                $mobile = if ($mobileNode) { $mobileNode.GetAttribute("Descriptor", "urn:com.workday/bsvc") } else { $null }
                Write-Log "Mobile: $mobile" -Level "DEBUG"
                
                Write-Log "Extracted values - Team_Member_ID: $teamMemberId, UPN: $upn, Mobile: $mobile" -Level "DEBUG"
                
                if ($teamMemberId -and $upn) {
                    $userData += [PSCustomObject]@{
                        Team_Member_ID = $teamMemberId
                        UPN = $upn
                        Mobile = $mobile
                    }
                }
                else {
                    Write-Log "Skipping entry - Missing required fields" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Error processing entry: $($_.Exception.Message)" -Level "ERROR"
                Write-Log "Entry data: $($entry.OuterXml)" -Level "ERROR"
                continue
            }
        }
        
        # Create array of users with both UPN and Mobile
        $usersWithMobile = $userData | Where-Object { $_.UPN -and $_.Mobile } | Select-Object Team_Member_ID, UPN, Mobile
        
        # Display UPN and Mobile data in a table
        Write-Host "`nUser Data:"
        Write-Host "----------"
        $userData | Format-Table -AutoSize
        
        # Display summary
        Write-Host "`nSummary:"
        Write-Host "--------"
        Write-Host "Total Records: $($userData.Count)"
        $mobileCount = ($userData | Where-Object {$_.Mobile} | Measure-Object).Count
        Write-Host "Records with Mobile Numbers: $mobileCount"
        
        # Display users with mobile numbers (ready for MFA)
        Write-Host "`nUsers Ready for MFA Setup:"
        Write-Host "-------------------------"
        if ($usersWithMobile) {
            $usersWithMobile | Format-Table -AutoSize
        }
        else {
            Write-Host "No users ready for MFA setup"
        }
        
        # Display sample of records without mobile numbers
        $noMobile = $userData | Where-Object {!$_.Mobile}
        if ($noMobile) {
            Write-Host "`nRecords without Mobile Numbers:"
            Write-Host "----------------------------"
            $noMobile | Format-Table -AutoSize
        }
        
        # Export users with mobile numbers to a CSV file for later use
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $exportFile = "$DataLogDir\mfa_ready_users_$timestamp.csv"
        $usersWithMobile | Export-Csv -Path $exportFile -NoTypeInformation
        Write-Log "Exported MFA-ready users to: $exportFile"
        
        # Store the result in a script-scoped variable
        $script:result = $usersWithMobile
    }
    else {
        Write-Log "No data was retrieved from Workday" -Level "ERROR"
        $script:result = $null
    }

    Write-Log "Test completed."
}

#=====================
# 5) EXECUTE SCRIPT
#=====================
Get-WorkdayMFAUsers

# Remove the redundant return statement
# $script:result 