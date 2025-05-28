# MFA Automation API Documentation

## Workday API Integration

### Feed Configuration
```powershell
$workdayConfig = @{
    Url = "https://wd5-impl-services1.workday.com/ccx/service/customreport2/gianteagle_preview/ISU_INT251/CR_INT251_New_Hire_Feed_to_Entra"
    Format = "simplexml"
}
```

### Required Fields
- `Team_Member_ID`: Unique identifier for the user
- `UPN`: User Principal Name (email)
- `Mobile`: Phone number for MFA

### XML Response Format
```xml
<wd:Report_Entry>
    <wd:Team_Member_ID>12345</wd:Team_Member_ID>
    <wd:UPN>user@domain.com</wd:UPN>
    <wd:Mobile>+1234567890</wd:Mobile>
</wd:Report_Entry>
```

## Microsoft Graph API Integration

### Authentication
```powershell
$graphHeaders = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}
```

### Endpoints Used

1. **Get User**
   ```
   GET https://graph.microsoft.com/v1.0/users/{userPrincipalName}
   ```

2. **Get Phone Methods**
   ```
   GET https://graph.microsoft.com/v1.0/users/{userPrincipalName}/authentication/phoneMethods
   ```

3. **Create Phone Method**
   ```
   POST https://graph.microsoft.com/v1.0/users/{userPrincipalName}/authentication/phoneMethods
   Body: {
       "phoneNumber": "+1234567890",
       "phoneType": "mobile"
   }
   ```

### Phone Method Behavior
- Only creates new phone methods if user has NO existing methods
- Skips users who already have any phone methods
- Does not update existing phone methods

### Rate Limiting
- Headers:
  - `X-RateLimit-Remaining`: Number of requests remaining
  - `X-RateLimit-Reset`: Time when the rate limit resets
  - `Retry-After`: Seconds to wait before retrying

## Secret Server API

### Base URL
```
https://creds.gianteagle.com/SecretServer
```

### Required Secrets

1. **Workday Credentials (ID: 42814)**
   ```json
   {
       "username": "string",
       "password": "string"
   }
   ```

2. **Graph API Credentials (ID: 42813)**
   ```json
   {
       "clientId": "string",
       "clientSecret": "string",
       "tenantId": "string"
   }
   ```

### API Methods

1. **Get Secret Details**
   ```powershell
   Get-SecretServerSecretDetails -SecretID $SecretID -TLS12
   ```

2. **Response Format**
   ```json
   {
       "items": [
           {
               "slug": "username",
               "itemValue": "string"
           },
           {
               "slug": "password",
               "itemValue": "string"
           }
       ]
   }
   ```

## Error Handling

### HTTP Status Codes

1. **Success Codes**
   - 200: OK
   - 201: Created
   - 204: No Content

2. **Error Codes**
   - 400: Bad Request
   - 401: Unauthorized
   - 403: Forbidden
   - 404: Not Found
   - 429: Too Many Requests

### Retry Logic

```powershell
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 5
    )
}
```

## Response Formats

### MFA Sync Report
```json
{
    "TotalUsers": 0,
    "SuccessCount": 0,
    "FailureCount": 0,
    "ProcessingTime": 0,
    "RateLimitInfo": {
        "ThrottleCount": 0,
        "FinalRemainingRequests": 0,
        "LastResetTime": "string"
    },
    "Errors": [
        {
            "UPN": "string",
            "Error": "string"
        }
    ],
    "SkippedUsers": [
        {
            "UPN": "string",
            "Reason": "string"
        }
    ]
}
```

### Log Entry Format
```
YYYY-MM-DD HH:mm:ss - LEVEL: Message
```

### Log Levels
- **INFO**: Standard operational messages
- **WARNING**: Non-critical issues
- **ERROR**: Critical failures
- **DEBUG**: Detailed information (only when -Verbose is used)

## Best Practices

1. **API Calls**
   - Use retry logic for transient failures
   - Implement rate limiting
   - Handle errors gracefully

2. **Security**
   - Never hardcode credentials
   - Use Secret Server for all secrets
   - Implement proper error handling

3. **Performance**
   - Use batch processing
   - Implement parallel processing
   - Monitor rate limits

4. **Logging**
   - Use -Verbose for detailed debugging
   - Log all API calls
   - Include error details
   - Track performance metrics 