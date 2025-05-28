<#
.SYNOPSIS
  Test setting a single user's MFA phone using a service principal,
  retrieving SP credentials from Secret Server.

.DESCRIPTION
  1. Retrieves secrets (client ID, client secret, tenant ID) from Secret Server.
  2. Obtains an OAuth token from Azure AD via client credentials.
  3. Sets or updates the user’s mobile MFA phone method using Microsoft Graph.

.NOTES
  - Requires your service principal have 'UserAuthenticationMethod.ReadWrite.All' 
    (application permission) with admin consent.
  - Adjust the secret structure, slugs, and user data to match your environment.
#>

# ---------------------------------------------------------
# 1) FUNCTION: Provided to Retrieve Secret from Secret Server
#    (You included this in your prompt; we’ll reuse it as-is.)
# ---------------------------------------------------------
function Get-SecretServerSecretDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$SecretID,
        [Parameter(Mandatory=$false)]
        [string]$SecretServerName = 'creds.gianteagle.com',
        [switch]$TLS12,
        [switch]$oAuth
    )

    if ($TLS12) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    $BaseURL = "https://$SecretServerName/SecretServer"
    $Arglist = @{}

    if ($oAuth) {
        # (Placeholder) Add your OAuth token retrieval logic here if needed.
        # For now, we'll assume Windows auth or integrated auth is enough.
        Write-Verbose "OAuth retrieval not implemented in this example."
    }
    else {
        $BaseURL += '/winauthwebservices/api/v1/secrets'
        $Arglist['UseDefaultCredentials'] = $true
    }

    $Arglist['Uri'] = "$BaseURL/$SecretID"
    Write-Verbose "Retrieving secret details from: $($Arglist['Uri'])"
    $SecretDetails = Invoke-RestMethod @Arglist
    return $SecretDetails
}

# ---------------------------------------------------------
# 2) GET SERVICE PRINCIPAL SECRETS FROM SECRET SERVER
# ---------------------------------------------------------
# Adjust SecretID to your actual ID that contains the clientId, clientSecret, tenantId
$SecretID = 42813

Write-Host "Retrieving credentials from Secret Server..."
$secretDetails = Get-SecretServerSecretDetails -SecretID $SecretID -TLS12

# We expect $secretDetails.items to contain something like:
#   slug: "clientId"     - Value: "YOUR-CLIENT-ID"
#   slug: "clientSecret" - Value: "YOUR-CLIENT-SECRET"
#   slug: "tenantId"     - Value: "YOUR-TENANT-ID"
# Adjust the slugs to match how your secrets are actually named.
$clientId     = ($secretDetails.items | Where-Object { $_.slug -eq "clientId" }).itemValue
$clientSecret = ($secretDetails.items | Where-Object { $_.slug -eq "clientSecret" }).itemValue
$tenantId     = ($secretDetails.items | Where-Object { $_.slug -eq "tenantId" }).itemValue

Write-Host "Client ID:    $clientId"
Write-Host "Tenant ID:    $tenantId"
Write-Host "ClientSecret: retrieved (not displaying)"

# ---------------------------------------------------------
# 3) GET AN ACCESS TOKEN USING CLIENT CREDENTIALS
# ---------------------------------------------------------
Write-Host "Obtaining Azure AD token via client credentials..."

$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
    grant_type    = "client_credentials"
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ErrorAction Stop
    $accessToken   = $tokenResponse.access_token
    Write-Host "Token acquired successfully."
}
catch {
    Write-Error "Failed to retrieve access token: $($_.Exception.Message)"
    return
}

# ---------------------------------------------------------
# 4) SET A SINGLE USER'S MFA PHONE METHOD
# ---------------------------------------------------------
# Adjust these to your test scenario
$UserPrincipal  = "Test.Shavensky@gianteagle.com"
$NewPhoneNumber = "+14122222222"  # E.164 recommended

Write-Host "Checking user's existing phone methods for: $UserPrincipal"

$graphHeaders = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

$phoneMethodsUrl = "https://graph.microsoft.com/v1.0/users/$UserPrincipal/authentication/phoneMethods"

try {
    $methodsResponse = Invoke-RestMethod -Uri $phoneMethodsUrl -Method GET -Headers $graphHeaders -ErrorAction Stop
    $existingMethods = $methodsResponse.value
    Write-Host "Retrieved existing phone methods. Count: $($existingMethods.Count)"
}
catch {
    Write-Error "Failed to retrieve phone methods for $($UserPrincipal): $($_.Exception.Message)"
    return
}

# Look for an existing 'mobile' method
$mobileMethod = $existingMethods | Where-Object { $_.phoneType -eq "mobile" }

if ($mobileMethod) {
    # If user has a mobile method, update it (PATCH).
    $methodId = $mobileMethod.id
    $patchBody = @{
        phoneNumber = $NewPhoneNumber
    } | ConvertTo-Json

    Write-Host "User already has a mobile phone method. Updating to $NewPhoneNumber..."

    $patchUrl = "$phoneMethodsUrl/$methodId"
    try {
        Invoke-RestMethod -Uri $patchUrl -Method PATCH -Headers $graphHeaders -Body $patchBody -ErrorAction Stop
        Write-Host "Mobile phone updated successfully."
    }
    catch {
        Write-Error "Failed to update mobile phone method for $($UserPrincipal): $($_.Exception.Message)"
    }
}
else {
    # If user has no mobile method, create one (POST).
    Write-Host "No mobile phone method found. Creating one..."

    $createBody = @{
        phoneNumber = $NewPhoneNumber
        phoneType   = "mobile"
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $phoneMethodsUrl -Method POST -Headers $graphHeaders -Body $createBody -ErrorAction Stop
        Write-Host "Mobile phone method created successfully."
    }
    catch {
        Write-Error "Failed to create mobile phone method for $($UserPrincipal): $($_.Exception.Message)"
    }
}

Write-Host "Done."
