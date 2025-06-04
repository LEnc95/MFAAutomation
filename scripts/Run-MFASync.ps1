<#
.SYNOPSIS
    Syncs phone numbers from Workday to Azure AD MFA, only if the user has no existing MFA phone methods.

.DESCRIPTION
    This script performs the following operations:
    1. Retrieves Azure AD + Workday credentials from Secret Server
    2. Retrieves data from a Workday RaaS feed (UPN & phone)
    3. Checks if user has any MFA phone methods. If none exist, creates a new mobile phone method
    4. Processes users in parallel batches with rate limit handling
    5. Logs all actions and errors to a file with rotation and compression
    6. Generates detailed reports in JSON and CSV formats

.PARAMETER DryRun
    When specified, the script will simulate the changes without actually modifying any MFA settings.

.PARAMETER BatchSize
    Number of users to process in each batch. Default is 100.

.PARAMETER MaxParallelBatches
    Maximum number of batches to process in parallel. Default is 5.

.PARAMETER Environment
    Environment to run the script in. Default is "Production".

.PARAMETER Verbose
    When specified, includes DEBUG level messages in the log file.

.NOTES
    - Requires Secret Server access for credentials
    - Requires appropriate Graph API permissions
    - Logs are automatically rotated and compressed
    - Rate limiting is handled automatically
    - Only adds phone numbers if user has NO existing phone methods

.EXAMPLE
    # Run in normal mode
    .\Run-MFASync.ps1

.EXAMPLE
    # Run with verbose logging
    .\Run-MFASync.ps1 -Verbose

.EXAMPLE
    # Run in dry run mode with custom batch size
    .\Run-MFASync.ps1 -DryRun -BatchSize 50

.OUTPUTS
    - JSON report with sync results
    - CSV file with MFA-ready users
    - Detailed log file with rotation
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$BatchSize,
    [int]$MaxParallelBatches,
    [string]$Environment
)

#=====================
# 1) CONFIG & LOGGING
#=====================
# Get the script's directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptPath

# Set up log directories relative to project root
$LogDir = Join-Path $projectRoot "logs"
$LogFile = Join-Path $LogDir "mfa_sync.log"
$DataLogDir = Join-Path $LogDir "WorkdayData"

# Log rotation settings
$MaxLogSize = 10MB
$MaxLogAge = 30  # days
$MaxLogFiles = 10
$MaxDataLogAge = 90  # days
$CompressLogs = $true  # Enable log compression

# Set default values
if (-not $BatchSize) { $BatchSize = 100 }
if (-not $MaxParallelBatches) { $MaxParallelBatches = 5 }
if (-not $Environment) { $Environment = "Production" }

function Initialize-Logging {
    # Create log directories if they don't exist
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir | Out-Null
        Write-Log "Created log directory: $LogDir" -Level "INFO"
    }
    if (!(Test-Path $DataLogDir)) {
        New-Item -ItemType Directory -Path $DataLogDir | Out-Null
        Write-Log "Created data log directory: $DataLogDir" -Level "INFO"
    }

    # Rotate logs if needed
    Update-LogRotation
}

function Compress-LogFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFilePath
    )
    
    try {
        $zipPath = "$LogFilePath.zip"
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            (Split-Path $LogFilePath),
            $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $false
        )
        
        # Remove original file after successful compression
        Remove-Item $LogFilePath -Force
        Write-Log "Compressed log file: $LogFilePath" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to compress log file $LogFilePath`: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Start-LogCleanup {
    param(
        [switch]$Force,
        [switch]$CompressOnly,
        [switch]$CleanupOnly
    )
    
    Write-Log "Starting log cleanup process..." -Level "INFO"
    
    if ($CompressOnly) {
        Write-Log "Compressing log files..." -Level "INFO"
        $logFiles = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*.log" | 
                   Where-Object { !$_.Name.EndsWith('.zip') }
        
        foreach ($log in $logFiles) {
            Compress-LogFile -LogFilePath $log.FullName
        }
        return
    }
    
    if ($CleanupOnly) {
        Write-Log "Cleaning up old log files..." -Level "INFO"
        $oldLogs = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*.log" | 
                  Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxLogAge) }
        
        foreach ($log in $oldLogs) {
            Remove-Item $log.FullName -Force
            Write-Log "Removed old log file: $($log.Name)" -Level "INFO"
        }
        
        $oldDataLogs = Get-ChildItem -Path $DataLogDir -Recurse | 
                      Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxDataLogAge) }
        
        foreach ($log in $oldDataLogs) {
            Remove-Item $log.FullName -Force
            Write-Log "Removed old data log: $($log.Name)" -Level "INFO"
        }
        return
    }
    
    # Full cleanup process
    Write-Log "Performing full log cleanup..." -Level "INFO"
    
    # 1. Compress old log files
    if ($CompressLogs) {
        $logFiles = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*.log" | 
                   Where-Object { !$_.Name.EndsWith('.zip') }
        
        foreach ($log in $logFiles) {
            Compress-LogFile -LogFilePath $log.FullName
        }
    }
    
    # 2. Remove old compressed logs
    $oldZips = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*.zip" | 
               Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxLogAge) }
    
    foreach ($zip in $oldZips) {
        Remove-Item $zip.FullName -Force
        Write-Log "Removed old compressed log: $($zip.Name)" -Level "INFO"
    }
    
    # 3. Clean up data logs
    $oldDataLogs = Get-ChildItem -Path $DataLogDir -Recurse | 
                  Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxDataLogAge) }
    
    foreach ($log in $oldDataLogs) {
        Remove-Item $log.FullName -Force
        Write-Log "Removed old data log: $($log.Name)" -Level "INFO"
    }
    
    # 4. Keep only the most recent logs
    $allLogs = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*" | 
              Sort-Object LastWriteTime -Descending | 
              Select-Object -Skip $MaxLogFiles
    
    foreach ($log in $allLogs) {
        Remove-Item $log.FullName -Force
        Write-Log "Removed excess log file: $($log.Name)" -Level "INFO"
    }
    
    Write-Log "Log cleanup completed successfully" -Level "INFO"
}

function Update-LogRotation {
    # Rotate main log file if it exceeds size limit
    if (Test-Path $LogFile) {
        $logFileSize = (Get-Item $LogFile).Length
        if ($logFileSize -gt $MaxLogSize) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $archiveLogFile = Join-Path $LogDir "mfa_sync_$timestamp.log"
            Move-Item -Path $LogFile -Destination $archiveLogFile -Force
            Write-Log "Rotated log file to: $archiveLogFile" -Level "INFO"
            
            # Compress the rotated log file if compression is enabled
            if ($CompressLogs) {
                Compress-LogFile -LogFilePath $archiveLogFile
            }
        }
    }
    
    # Clean up old log files
    $oldLogs = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*.log" | 
               Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxLogAge) }
    foreach ($log in $oldLogs) {
        Remove-Item $log.FullName -Force
        Write-Log "Removed old log file: $($log.Name)" -Level "INFO"
    }
    
    # Clean up old data logs
    $oldDataLogs = Get-ChildItem -Path $DataLogDir -Recurse | 
                  Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxDataLogAge) }
    foreach ($log in $oldDataLogs) {
        Remove-Item $log.FullName -Force
        Write-Log "Removed old data log: $($log.Name)" -Level "INFO"
    }
    
    # Keep only the most recent log files
    $logFiles = Get-ChildItem -Path $LogDir -Filter "mfa_sync_*" | 
                Sort-Object LastWriteTime -Descending | 
                Select-Object -Skip $MaxLogFiles
    foreach ($log in $logFiles) {
        Remove-Item $log.FullName -Force
        Write-Log "Removed excess log file: $($log.Name)" -Level "INFO"
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,
        [string] $Level = "INFO"
    )
    
    # Skip DEBUG level messages unless -Verbose is used
    if ($Level -eq "DEBUG" -and -not $VerbosePreference -eq 'Continue') { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Level`: $Message"
    
    # Write to console with color based on level
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARNING" { Write-Host $entry -ForegroundColor Yellow }
        "DEBUG" { Write-Host $entry -ForegroundColor Gray }
        default { Write-Host $entry }
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $entry -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-DataFile {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Data,
        
        [Parameter(Mandatory = $true)]
        [string] $FileName,
        
        [Parameter(Mandatory = $true)]
        [string] $FileType
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filePath = Join-Path $DataLogDir "$FileName`_$timestamp.$FileType"
    
    try {
        switch ($FileType) {
            "json" { 
                if ($Data -is [string]) {
                    $Data | Out-File $filePath -Encoding UTF8
                } else {
                    $Data | ConvertTo-Json -Depth 10 | Out-File $filePath -Encoding UTF8
                }
            }
            "csv" { 
                if ($Data -is [array]) {
                    $Data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
                } else {
                    Write-Log "Warning: Data is not an array, cannot export as CSV" -Level "WARNING"
                    return $null
                }
            }
            default { 
                if ($Data -is [string]) {
                    $Data | Out-File $filePath -Encoding UTF8
                } else {
                    $Data | ConvertTo-Json -Depth 10 | Out-File $filePath -Encoding UTF8
                }
            }
        }
        Write-Log "Successfully exported $FileType file: $filePath" -Level "INFO"
        return $filePath
    }
    catch {
        Write-Log "Failed to export $FileType file: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Initialize logging
Initialize-Logging

#=====================
# 2) SECRET SERVER FUNCTIONS
#=====================
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
        UseDefaultCredentials = $true
    }

    Write-Log "Retrieving secret details from Secret Server..."
    $SecretDetails = Invoke-RestMethod @Arglist
    return $SecretDetails
}

#=====================
# 3) WORKDAY CONFIG
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
# 4) GRAPH API CONFIG
#=====================
$graphSecretID = 42813  # Your Secret Server ID for Graph API credentials

#=====================
# 5) WORKDAY DATA RETRIEVAL
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
# 6) GRAPH API FUNCTIONS
#=====================
function Format-PhoneNumber {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PhoneNumber
    )

    # Remove all non-numeric characters except '+' if it's at the start
    $hasPlus = $PhoneNumber.StartsWith('+')
    $numericOnly = $PhoneNumber -replace '[^0-9]', ''
    
    # If the number started with '+', add it back
    if ($hasPlus) {
        $numericOnly = "+$numericOnly"
    }

    # Handle different number formats
    switch -Regex ($numericOnly) {
        '^\+\d{7,15}$' {
            # Already in E.164 format with country code
            return $numericOnly
        }
        '^1\d{10}$' {
            # US number without + prefix
            return "+$numericOnly"
        }
        '^\d{10}$' {
            # US number without country code
            return "+1$numericOnly"
        }
        '^\d{7,15}$' {
            # International number without + prefix
            return "+$numericOnly"
        }
        default {
            Write-Log "Invalid phone number format: $PhoneNumber (Length: $($numericOnly.Length))" -Level "WARNING"
            return $null
        }
    }
}

function Get-GraphToken {
    param (
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$TenantId
    )

    Write-Log "Obtaining Azure AD token via client credentials..."
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ErrorAction Stop
        Write-Log "Token acquired successfully."
        return $tokenResponse.access_token
    }
    catch {
        Write-Log "Failed to retrieve access token: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Add rate limit tracking variables at the top of the script
$script:rateLimitInfo = @{
    RemainingRequests = 0
    ResetTime = $null
    LastRequestTime = $null
    ThrottleCount = 0
}

function Update-RateLimitInfo {
    param(
        [hashtable]$Headers
    )
    
    if ($Headers.ContainsKey('X-RateLimit-Remaining')) {
        $script:rateLimitInfo.RemainingRequests = [int]$Headers['X-RateLimit-Remaining']
        Write-Log "Rate Limit - Remaining requests: $($script:rateLimitInfo.RemainingRequests)" -Level "INFO"
    }
    
    if ($Headers.ContainsKey('X-RateLimit-Reset')) {
        $script:rateLimitInfo.ResetTime = [datetime]::FromUnixTimeSeconds([int]$Headers['X-RateLimit-Reset'])
        Write-Log "Rate Limit - Reset time: $($script:rateLimitInfo.ResetTime)" -Level "INFO"
    }
    
    $script:rateLimitInfo.LastRequestTime = Get-Date
}

function Test-RateLimit {
    param(
        [int]$RequiredRequests = 1
    )
    
    if ($script:rateLimitInfo.RemainingRequests -lt $RequiredRequests) {
        $waitTime = ($script:rateLimitInfo.ResetTime - (Get-Date)).TotalSeconds
        if ($waitTime -gt 0) {
            Write-Log "Rate limit reached. Waiting $([math]::Ceiling($waitTime)) seconds for reset..." -Level "WARNING"
            Start-Sleep -Seconds $waitTime
            return $true
        }
    }
    return $false
}

function Set-UserMFAPhone {
    param (
        [string]$UserPrincipal,
        [string]$PhoneNumber,
        [hashtable]$Headers
    )

    Write-Log "Processing MFA phone for user: $UserPrincipal"
    $phoneMethodsUrl = "https://graph.microsoft.com/v1.0/users/$UserPrincipal/authentication/phoneMethods"

    try {
        # Check rate limits before making requests
        Test-RateLimit -RequiredRequests 1  # We only need 1 request: GET

        # Get existing methods
        $methodsResponse = Invoke-RestMethod -Uri $phoneMethodsUrl -Method GET -Headers $Headers -ErrorAction Stop
        Update-RateLimitInfo -Headers $methodsResponse.Headers
        $existingMethods = $methodsResponse.value

        if ($existingMethods -and $existingMethods.Count -gt 0) {
            Write-Log "Skipping $UserPrincipal because they already have $($existingMethods.Count) phone method(s)" -Level "INFO"
            return $true  # Return true since this is a valid skip case
        }
        else {
            # No phone methods found, create a new one
            $createBody = @{
                phoneNumber = $PhoneNumber
                phoneType   = "mobile"
            } | ConvertTo-Json

            Write-Log "Creating new mobile phone method for $UserPrincipal..."
            $null = Invoke-RestMethod -Uri $phoneMethodsUrl -Method POST -Headers $Headers -Body $createBody -ErrorAction Stop
            Write-Log "Mobile phone method created successfully for $UserPrincipal"
            return $true
        }
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 429) {
            $script:rateLimitInfo.ThrottleCount++
            Write-Log "Rate limit exceeded for user $UserPrincipal. Throttle count: $($script:rateLimitInfo.ThrottleCount)" -Level "WARNING"
            $retryAfter = $_.Exception.Response.Headers['Retry-After']
            if ($retryAfter) {
                Write-Log "Waiting $retryAfter seconds before retry..." -Level "WARNING"
                Start-Sleep -Seconds $retryAfter
                return Set-UserMFAPhone -UserPrincipal $UserPrincipal -PhoneNumber $PhoneNumber -Headers $Headers
            }
        }
        Write-Log "Failed to process MFA phone for ${UserPrincipal}: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 5
    )
    
    $attempt = 1
    while ($attempt -le $MaxAttempts) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -eq $MaxAttempts) { throw }
            Write-Log "Attempt $attempt failed. Retrying in $DelaySeconds seconds..." -Level "WARNING"
            Start-Sleep -Seconds $DelaySeconds
            $DelaySeconds *= 2
            $attempt++
        }
    }
}

function Invoke-BatchProcessing {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Users,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory=$false)]
        [switch]$DryRun
    )
    
    $batchResults = @()
    $batchStartTime = Get-Date
    
    Write-Log "Starting batch processing. Current rate limit status: $($script:rateLimitInfo.RemainingRequests) requests remaining" -Level "INFO"
    
    foreach ($user in $Users) {
        $userStartTime = Get-Date
        
        if ($DryRun) {
            Write-Log "DRY RUN - Would process user: $($user.UPN) - Original phone: $($user.Original_Mobile) - Formatted phone: $($user.Mobile)"
            $user.Success = $true
        }
        else {
            # Check if user exists in Entra ID
            $userExists = Invoke-WithRetry -ScriptBlock {
                Test-UserExists -UserPrincipal $user.UPN -Headers $Headers
            }
            
            if ($userExists) {
                $result = Invoke-WithRetry -ScriptBlock {
                    Set-UserMFAPhone -UserPrincipal $user.UPN -PhoneNumber $user.Mobile -Headers $Headers
                }
                $user.Success = $result
            }
            else {
                Write-Log "User $($user.UPN) not found in Entra ID" -Level "WARNING"
                $user.Success = $false
                $user.Error = "User not found in Entra ID"
            }
        }
        
        $user.ProcessingTime = (Get-Date) - $userStartTime
        $batchResults += $user
        
        # Log rate limit status every 10 users
        if ($batchResults.Count % 10 -eq 0) {
            Write-Log "Processed $($batchResults.Count) users in current batch. Rate limit status: $($script:rateLimitInfo.RemainingRequests) requests remaining" -Level "INFO"
        }
    }
    
    $batchDuration = (Get-Date) - $batchStartTime
    Write-Log "Batch completed in $($batchDuration.TotalSeconds) seconds. Final rate limit status: $($script:rateLimitInfo.RemainingRequests) requests remaining" -Level "INFO"
    
    return $batchResults
}

function Export-SyncReport {
    param(
        [array]$Results,
        [string]$OutputPath
    )
    
    $report = @{
        TotalUsers = $Results.Count
        SuccessCount = ($Results | Where-Object { $_.Success }).Count
        FailureCount = ($Results | Where-Object { !$_.Success }).Count
        ProcessingTime = $Results.ProcessingTime
        RateLimitInfo = @{
            ThrottleCount = $script:rateLimitInfo.ThrottleCount
            FinalRemainingRequests = $script:rateLimitInfo.RemainingRequests
            LastResetTime = $script:rateLimitInfo.ResetTime
        }
        Errors = $Results | Where-Object { !$_.Success } | Select-Object UPN, Error
    }
    
    $report | ConvertTo-Json | Out-File $OutputPath
}

function Test-UserExists {
    param(
        [string]$UserPrincipal,
        [hashtable]$Headers
    )
    
    try {
        $userUrl = "https://graph.microsoft.com/v1.0/users/$UserPrincipal"
        $null = Invoke-RestMethod -Uri $userUrl -Headers $Headers -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

#=====================
# 4) MAIN FUNCTION
#=====================
function Get-WorkdayMFAUsers {
    Write-Log "Starting Workday to Graph MFA sync..."

    # Initialize arrays
    $script:skippedUsers = @()
    $script:allResults = @()
    $script:successCount = 0
    $script:failureCount = 0

    # Get the data
    $workdayData = Get-WorkdayData -Config $workdayConfig

    if ($workdayData) {
        Write-Log "Data retrieved successfully. Processing entries..."
        
        # Log the raw data
        Write-DataLog -Data $workdayData
        
        # Create XML document
        [xml]$xmlDoc = $workdayData
        
        # Add namespace manager
        $nsManager = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $nsManager.AddNamespace("wd", "urn:com.workday/bsvc")
        
        # Extract data using XPath
        $entries = $xmlDoc.SelectNodes("//wd:Report_Entry", $nsManager)
        
        Write-Log "Found $($entries.Count) total entries in Workday feed"
        
        # Process entries
        $userData = @()
        $skippedUsers = @()
        foreach ($entry in $entries) {
            Write-Log "Processing entry XML: $($entry.OuterXml)" -Level "DEBUG"
            
            try {
                # Get Team Member ID
                $teamMemberId = $entry.SelectSingleNode("wd:Team_Member_ID", $nsManager).InnerText
                Write-Log "Team Member ID: $teamMemberId" -Level "DEBUG"
                
                # Get UPN
                $upnNode = $entry.SelectSingleNode("wd:UPN", $nsManager)
                $upn = $upnNode.GetAttribute("Descriptor")
                Write-Log "UPN: $upn" -Level "DEBUG"
                
                # Get Mobile
                $mobileNode = $entry.SelectSingleNode("wd:Mobile", $nsManager)
                $mobile = if ($mobileNode) { $mobileNode.GetAttribute("Descriptor") } else { $null }
                Write-Log "Mobile: $mobile" -Level "DEBUG"
                
                Write-Log "Extracted values - Team_Member_ID: $teamMemberId, UPN: $upn, Mobile: $mobile" -Level "DEBUG"
                
                if ($teamMemberId -and $upn) {
                    # Format the phone number if it exists
                    $formattedPhone = if ($mobile) { Format-PhoneNumber -PhoneNumber $mobile } else { $null }
                    
                    if ($formattedPhone) {
                        $userData += [PSCustomObject]@{
                            Team_Member_ID = $teamMemberId
                            UPN = $upn
                            Mobile = $formattedPhone
                            Original_Mobile = $mobile
                            Success = $false
                            Error = $null
                            ProcessingTime = $null
                        }
                        Write-Log "Added user to MFA-ready list: $upn" -Level "DEBUG"
                    }
                    else {
                        $skippedUsers += [PSCustomObject]@{
                            UPN = $upn
                            Reason = "Invalid phone number format: $mobile"
                        }
                        Write-Log "Skipping user $upn due to invalid phone number format: $mobile" -Level "WARNING"
                    }
                }
                else {
                    $skippedUsers += [PSCustomObject]@{
                        UPN = $upn
                        Reason = "Missing required fields (Team Member ID or UPN)"
                    }
                    Write-Log "Skipping entry - Missing required fields" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Error processing entry: $($_.Exception.Message)" -Level "ERROR"
                Write-Log "Entry data: $($entry.OuterXml)" -Level "ERROR"
                continue
            }
        }
        
        Write-Log "Found $($userData.Count) users with valid UPN and mobile numbers"
        
        # Store the result in a script-scoped variable
        $script:result = $userData
    }
    else {
        Write-Log "No data was retrieved from Workday" -Level "ERROR"
        $script:result = $null
    }

    return $script:result
}

#=====================
# 6) MAIN EXECUTION
#=====================
Write-Log "Starting Workday to Graph MFA sync..."
$startTime = Get-Date

# Get Workday data
$workdayData = Get-WorkdayData -Config $workdayConfig
if (!$workdayData) {
    Write-Log "Failed to retrieve Workday data. Exiting." -Level "ERROR"
    exit
}

# Process Workday data
[xml]$xmlDoc = $workdayData
$nsManager = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
$nsManager.AddNamespace("wd", "urn:com.workday/bsvc")
$entries = $xmlDoc.SelectNodes("//wd:Report_Entry", $nsManager)

Write-Log "Found $($entries.Count) total entries in Workday feed"

# Create array of users with both UPN and Mobile
$usersWithMobile = @()
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
            # Format the phone number if it exists
            $formattedPhone = if ($mobile) { Format-PhoneNumber -PhoneNumber $mobile } else { $null }
            
            if ($formattedPhone) {
                $usersWithMobile += [PSCustomObject]@{
                    Team_Member_ID = $teamMemberId
                    UPN = $upn
                    Mobile = $formattedPhone
                    Original_Mobile = $mobile
                    Success = $false
                    Error = $null
                    ProcessingTime = $null
                }
                Write-Log "Added user to MFA-ready list: $upn" -Level "DEBUG"
            }
            else {
                $script:skippedUsers += [PSCustomObject]@{
                    UPN = $upn
                    Reason = "Invalid phone number format: $mobile"
                }
                Write-Log "Skipping user $upn due to invalid phone number format: $mobile" -Level "WARNING"
            }
        }
        else {
            $script:skippedUsers += [PSCustomObject]@{
                UPN = $upn
                Reason = "Missing required fields (Team Member ID or UPN)"
            }
            Write-Log "Skipping entry - Missing required fields" -Level "WARNING"
        }
    }
    catch {
        Write-Log "Error processing entry: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Entry data: $($entry.OuterXml)" -Level "ERROR"
        continue
    }
}

Write-Log "Found $($usersWithMobile.Count) users with valid UPN and mobile numbers"

# Get Graph API credentials
$secretDetails = Get-SecretServerSecretDetails -SecretID $graphSecretID -TLS12
$clientId = ($secretDetails.items | Where-Object { $_.slug -eq "clientId" }).itemValue
$clientSecret = ($secretDetails.items | Where-Object { $_.slug -eq "clientSecret" }).itemValue
$tenantId = ($secretDetails.items | Where-Object { $_.slug -eq "tenantId" }).itemValue

# Get Graph API token
$accessToken = Get-GraphToken -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId
if (!$accessToken) {
    Write-Log "Failed to obtain Graph API token. Exiting." -Level "ERROR"
    exit
}

# Set up Graph API headers
$graphHeaders = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# Process users in parallel batches with error handling
$batches = @()
for ($i = 0; $i -lt $usersWithMobile.Count; $i += $BatchSize) {
    $batch = $usersWithMobile | Select-Object -Skip $i -First $BatchSize
    $batches += ,$batch
}

Write-Log "Processing $($batches.Count) batches with up to $MaxParallelBatches parallel batches"
Write-Log "Total users to process: $($usersWithMobile.Count)"

# Define the script block for processing users
$processUserScript = {
    param($User, $Headers, $DryRun)
    
    function Test-UserExists {
        param(
            [string]$UserPrincipal,
            [hashtable]$Headers
        )
        
        try {
            $userUrl = "https://graph.microsoft.com/v1.0/users/$UserPrincipal"
            $null = Invoke-RestMethod -Uri $userUrl -Headers $Headers -ErrorAction Stop
            return $true
        }
        catch {
            return $false
        }
    }

    function Set-UserMFAPhone {
        param (
            [string]$UserPrincipal,
            [string]$PhoneNumber,
            [hashtable]$Headers
        )

        Write-Log "Processing MFA phone for user: $UserPrincipal"
        $phoneMethodsUrl = "https://graph.microsoft.com/v1.0/users/$UserPrincipal/authentication/phoneMethods"

        try {
            # Get existing methods
            $methodsResponse = Invoke-RestMethod -Uri $phoneMethodsUrl -Method GET -Headers $Headers -ErrorAction Stop
            $existingMethods = $methodsResponse.value

            if ($existingMethods -and $existingMethods.Count -gt 0) {
                Write-Log "Skipping $UserPrincipal because they already have $($existingMethods.Count) phone method(s)" -Level "INFO"
                return $true  # Return true since this is a valid skip case
            }
            else {
                # No phone methods found, create a new one
                $createBody = @{
                    phoneNumber = $PhoneNumber
                    phoneType   = "mobile"
                } | ConvertTo-Json

                Write-Log "Creating new mobile phone method for $UserPrincipal..."
                $null = Invoke-RestMethod -Uri $phoneMethodsUrl -Method POST -Headers $Headers -Body $createBody -ErrorAction Stop
                Write-Log "Mobile phone method created successfully for $UserPrincipal"
                return $true
            }
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 429) {
                $script:rateLimitInfo.ThrottleCount++
                Write-Log "Rate limit exceeded for user $UserPrincipal. Throttle count: $($script:rateLimitInfo.ThrottleCount)" -Level "WARNING"
                $retryAfter = $_.Exception.Response.Headers['Retry-After']
                if ($retryAfter) {
                    Write-Log "Waiting $retryAfter seconds before retry..." -Level "WARNING"
                    Start-Sleep -Seconds $retryAfter
                    return Set-UserMFAPhone -UserPrincipal $UserPrincipal -PhoneNumber $PhoneNumber -Headers $Headers
                }
            }
            Write-Log "Failed to process MFA phone for ${UserPrincipal}: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
    }

    function Write-Log {
        param(
            [Parameter(Mandatory = $true)]
            [string] $Message,
            [string] $Level = "INFO"
        )
        $entry = "{0} - {1}: {2}" -f (Get-Date), $Level, $Message
        Write-Host $entry
    }

    try {
        Write-Log "Processing user: $($User.UPN)" -Level "DEBUG"
        if ($DryRun) {
            Write-Log "DRY RUN - Would process user: $($User.UPN) - Original phone: $($User.Original_Mobile) - Formatted phone: $($User.Mobile)"
            return [PSCustomObject]@{
                UPN = $User.UPN
                Success = $true
                Error = $null
            }
        }
        else {
            # Check if user exists in Entra ID
            $userExists = Test-UserExists -UserPrincipal $User.UPN -Headers $Headers
            
            if ($userExists) {
                Write-Log "User exists in Entra ID: $($User.UPN)" -Level "DEBUG"
                $success = Set-UserMFAPhone -UserPrincipal $User.UPN -PhoneNumber $User.Mobile -Headers $Headers
                Write-Log "MFA phone set result for $($User.UPN): $success" -Level "DEBUG"
                return [PSCustomObject]@{
                    UPN = $User.UPN
                    Success = $success
                    Error = if (-not $success) { "Failed to set MFA phone" } else { $null }
                }
            }
            else {
                Write-Log "User $($User.UPN) not found in Entra ID" -Level "WARNING"
                return [PSCustomObject]@{
                    UPN = $User.UPN
                    Success = $false
                    Error = "User not found in Entra ID"
                }
            }
        }
    }
    catch {
        Write-Log "Error processing user $($User.UPN): $($_.Exception.Message)" -Level "ERROR"
        return [PSCustomObject]@{
            UPN = $User.UPN
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

try {
    # Create a runspace pool for parallel processing
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxParallelBatches)
    $runspacePool.Open()

    $runspaces = @()
    $batchNumber = 1

    foreach ($batch in $batches) {
        $batchUserCount = $batch.Count
        Write-Log "Processing batch $batchNumber with $batchUserCount users" -Level "DEBUG"
        Write-Log "Batch users: $($batch | ForEach-Object { $_.UPN })" -Level "DEBUG"
        
        # Process each user in the batch
        foreach ($user in $batch) {
            $runspace = [powershell]::Create().AddScript($processUserScript).AddArgument($user).AddArgument($graphHeaders).AddArgument($DryRun)
            
            $runspace.RunspacePool = $runspacePool
            $runspaces += [PSCustomObject]@{
                Runspace = $runspace
                BatchNumber = $batchNumber
                Handle = $runspace.BeginInvoke()
            }
        }
        
        Write-Log "Started batch $batchNumber of $($batches.Count)"
        $batchNumber++

        # Add a small delay between batch starts to prevent API throttling
        Start-Sleep -Milliseconds 200
    }

    # Wait for all batches to complete and collect results
    $script:allResults = @()
    foreach ($runspace in $runspaces) {
        try {
            $results = $runspace.Runspace.EndInvoke($runspace.Handle)
            if ($results) {
                Write-Log "Received results from batch $($runspace.BatchNumber)" -Level "DEBUG"
                Write-Log "Results for batch $($runspace.BatchNumber): $($results.UPN): $($results.Success)" -Level "DEBUG"
                # Update the original user object with the results
                $user = $usersWithMobile | Where-Object { $_.UPN -eq $results.UPN }
                if ($user) {
                    $user.Success = [bool]$results.Success
                    $user.Error = $results.Error
                    $script:allResults += $user
                    Write-Log "Updated user $($user.UPN) with success status: $($user.Success)" -Level "DEBUG"
                }
            }
            else {
                Write-Log "No results received from batch $($runspace.BatchNumber)" -Level "WARNING"
            }
            Write-Log "Completed batch $($runspace.BatchNumber) of $($batches.Count)"
        }
        catch {
            Write-Log "Error collecting results from batch $($runspace.BatchNumber): $($_.Exception.Message)" -Level "ERROR"
        }
        finally {
            $runspace.Runspace.Dispose()
        }
    }

    Write-Log "Total results collected: $($script:allResults.Count)" -Level "DEBUG"

    # Generate and export report
    $script:successCount = 0
    $script:failureCount = 0
    foreach ($result in $script:allResults) {
        if ($result.Success -eq $true) {
            $script:successCount++
        }
        else {
            $script:failureCount++
        }
    }

    Write-Log "Success count: $script:successCount" -Level "DEBUG"
    Write-Log "Failure count: $script:failureCount" -Level "DEBUG"

    $reportData = @{
        TotalUsers = $script:allResults.Count
        SuccessCount = $script:successCount
        FailureCount = $script:failureCount
        ProcessingTime = $totalTime.TotalMinutes
        RateLimitInfo = @{
            ThrottleCount = $script:rateLimitInfo.ThrottleCount
            FinalRemainingRequests = $script:rateLimitInfo.RemainingRequests
            LastResetTime = $script:rateLimitInfo.ResetTime
        }
        Errors = $script:allResults | Where-Object { !$_.Success } | Select-Object UPN, Error
        SkippedUsers = $script:skippedUsers | Select-Object UPN, Reason
    }

    $reportPath = Export-DataFile -Data $reportData -FileName "mfa_sync_report" -FileType "json"
    $csvPath = Export-DataFile -Data $script:allResults -FileName "mfa_ready_users" -FileType "csv"

    # Log final summary
    $endTime = Get-Date
    $totalTime = $endTime - $startTime

    Write-Log "Sync completed in $([math]::Round($totalTime.TotalMinutes, 2)) minutes" -Level "INFO"
    Write-Log "Total Users: $($script:allResults.Count)" -Level "INFO"
    Write-Log "Successful: $script:successCount" -Level "INFO"
    Write-Log "Failed: $script:failureCount" -Level "INFO"
    Write-Log "Report exported to: $reportPath" -Level "INFO"
    Write-Log "MFA-ready users exported to: $csvPath" -Level "INFO"

    if ($DryRun) {
        Write-Log "This was a dry run - no changes were made to Entra ID" -Level "WARNING"
    }
}
catch {
    Write-Log "Error in parallel processing: $($_.Exception.Message)" -Level "ERROR"
}
finally {
    if ($runspacePool) {
        $runspacePool.Close()
        $runspacePool.Dispose()
    }
} 