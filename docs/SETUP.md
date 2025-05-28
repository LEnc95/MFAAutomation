# MFA Automation Setup Guide

## Prerequisites

1. **PowerShell Requirements**
   - PowerShell 5.1 or later
   - Required modules:
     - Microsoft.Graph
     - SecretServer

2. **Access Requirements**
   - Secret Server access
   - Workday feed access
   - Microsoft Graph API permissions

3. **Required Permissions**
   - Microsoft Graph API: `UserAuthenticationMethod.ReadWrite.All`
   - Workday API access
   - Secret Server access

## Installation Steps

1. **Clone the Repository**
   ```powershell
   git clone [repository-url]
   cd MFAAutomation
   ```

2. **Install Required Modules**
   ```powershell
   Install-Module Microsoft.Graph -Force
   Install-Module SecretServer -Force
   ```

3. **Configure Secret Server**
   - Create two secrets in Secret Server:
     1. Workday API credentials (ID: 42814)
        - Required fields: username, password
     2. Graph API credentials (ID: 42813)
        - Required fields: clientId, clientSecret, tenantId

4. **Verify Directory Structure**
   ```
   MFAAutomation/
   ├── scripts/
   │   ├── Run-MFASync.ps1
   │   ├── TestWorkdayFeed.ps1
   │   └── TestGrapgAPI.ps1
   │   └── Cleanup-WorkdayData.ps1
   ├── logs/
   ├── docs/
   └── README.md
   ```

## Configuration

1. **Secret Server Configuration**
   - Verify access to Secret IDs:
     - 42814 (Workday credentials)
     - 42813 (Graph API credentials)

2. **Workday Feed Configuration**
   - Verify access to feed:
     - CR_INT251_New_Hire_Feed_to_Entra
   - Test feed access:
     ```powershell
     .\scripts\TestWorkdayFeed.ps1
     ```

3. **Graph API Configuration**
   - Verify permissions:
     - User.ReadWrite.All
     - AuthenticationMethod.ReadWrite.All
   - Test API access:
     ```powershell
     .\scripts\TestGraphAPI.ps1
     ```

## Usage

1. **Running the Sync**
   ```powershell
   # Normal run
   .\scripts\Run-MFASync.ps1

   # With verbose logging
   .\scripts\Run-MFASync.ps1 -Verbose

   # Dry run mode
   .\scripts\Run-MFASync.ps1 -DryRun
   ```

2. **Monitoring Progress**
   - Check log file: `logs\mfa_sync.log`
   - Review reports in `reports` directory
   - Monitor console output

3. **Troubleshooting**
   - Enable verbose logging with `-Verbose`
   - Check error logs
   - Review skipped users report

## Maintenance

1. **Log Management**
   - Logs are automatically rotated
   - Old logs are compressed
   - Retention period: 30 days

2. **Report Management**
   - Reports are generated per run
   - JSON and CSV formats available
   - Historical data maintained

3. **Regular Tasks**
   - Monitor log sizes
   - Review error patterns
   - Check skipped users

## Security

1. **Credential Management**
   - All credentials stored in Secret Server
   - No hardcoded secrets
   - Regular rotation required

2. **Access Control**
   - Least privilege principle
   - Regular access reviews
   - Audit logging enabled

## Support

For issues or questions:
1. Check the logs
2. Review documentation
3. Contact the development team 