# MFA Automation

## Overview
This project automates the synchronization of Multi-Factor Authentication (MFA) settings between Workday and Microsoft Entra ID (formerly Azure AD).

## Directory Structure
```
MFAAutomation/
├── scripts/
│   ├── Run-MFASync.ps1      # Main MFA sync script
│   ├── TestWorkdayFeed.ps1  # Workday feed testing
│   ├── TestGraphAPI.ps1     # Graph API testing
│   └── Cleanup-WorkdayData.ps1  # Data cleanup
├── logs/
│   └── WorkdayData/         # Sync reports
├── docs/
│   ├── ARCHITECTURE.md      # System architecture
│   ├── API.md              # API documentation
│   ├── SETUP.md            # Setup guide
│   └── PROJECT_CHARTER.md  # Project details
└── README.md
```

## Usage

### Running the Sync
```powershell
.\scripts\Run-MFASync.ps1 [-DryRun] [-BatchSize <int>] [-MaxParallelBatches <int>] [-Environment <string>]
```

### Parameters
- `-DryRun`: Simulate changes without modifying MFA settings
- `-BatchSize`: Number of users to process in each batch (default: 100)
- `-MaxParallelBatches`: Maximum number of parallel batches (default: 5)
- `-Environment`: Environment to run in (default: "Production")
- `-Verbose`: Enable detailed logging

### Examples
```powershell
# Normal run
.\scripts\Run-MFASync.ps1

# With verbose logging
.\scripts\Run-MFASync.ps1 -Verbose

# Dry run with custom batch size
.\scripts\Run-MFASync.ps1 -DryRun -BatchSize 50
```

## Logs and Reports
- Main log: `logs/mfa_sync.log`
- Sync reports: `logs/WorkdayData/`
- Logs are automatically rotated and compressed

## Documentation
See the `docs` directory for detailed documentation:
- [Architecture](docs/ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Setup Guide](docs/SETUP.md)
- [Project Charter](docs/PROJECT_CHARTER.md)

## Prerequisites

- PowerShell 5.1 or later
- Access to Workday API
- Microsoft Graph API permissions
- Secret Server access for credential management

## Required Permissions

- Microsoft Graph API: `UserAuthenticationMethod.ReadWrite.All`
- Workday API access
- Secret Server access

## Configuration

### Secret Server Setup

1. Create two secrets in Secret Server:
   - Workday API credentials (ID: 42814)
     - Required fields: username, password
   - Graph API credentials (ID: 42813)
     - Required fields: clientId, clientSecret, tenantId

2. Ensure the script has access to these secrets in Secret Server

### Workday Configuration

The Workday feed URL is configured in the script:
```powershell
$workdayConfig = @{
    Url = "https://wd5-impl-services1.workday.com/ccx/service/customreport2/gianteagle_preview/ISU_INT251/CR_INT251_New_Hire_Feed_to_Entra"
    Format = "simplexml"
}
```

## Security

- All credentials are stored in Secret Server
- No sensitive data is stored in the repository
- API tokens are managed securely
- Access to secrets is controlled through Secret Server permissions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please contact the IT Operations team. 