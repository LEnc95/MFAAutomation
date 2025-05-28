# MFA Automation Project Charter

## Project Owner
Luke/Brian

The MFA Automation project aims to streamline the process of configuring Multi-Factor Authentication (MFA) settings for new employees by automatically synchronizing phone numbers from Workday to Microsoft Entra ID (formerly Azure AD).

## Objectives

1. **Automation**
   - Eliminate manual MFA configuration
   - Reduce human error
   - Improve efficiency

2. **Security**
   - Ensure consistent MFA setup
   - Maintain audit trail
   - Follow security best practices

3. **Reliability**
   - Handle errors gracefully
   - Provide detailed logging
   - Support troubleshooting

## Scope

### In Scope
- Automated phone number sync from Workday
- MFA method creation in Entra ID
- Logging and reporting
- Error handling and retries
- Rate limit management

### Out of Scope
- Manual MFA configuration
- User training
- Support for other MFA methods
- User communication

## Deliverables

1. **Core Scripts**
   - `Run-MFASync.ps1`: Main sync script
   - `TestWorkdayFeed.ps1`: Feed testing
   - `TestGraphAPI.ps1`: API testing

2. **Documentation**
   - Setup guide
   - Architecture documentation
   - API documentation
   - Project charter

3. **Reports**
   - Sync reports
   - Error logs
   - Audit trails

## Success Criteria

1. **Efficiency**
   - Reduced manual work
   - Faster MFA setup
   - Automated reporting

2. **Reliability**
   - 99.9% success rate
   - Proper error handling
   - Detailed logging

3. **Security**
   - Secure credential management
   - Audit trail maintenance
   - Access control

## Timeline

1. **Phase 1: Development**
   - Script development
   - Testing
   - Documentation

2. **Phase 2: Testing**
   - UAT
   - Performance testing
   - Security review

3. **Phase 3: Deployment**
   - Production deployment
   - Monitoring
   - Support

## Team

- Project Owner: IT Operations
- Developers: Automation Team
- Support: IT Operations
- Security: Security Team

## Risks

1. **Technical**
   - API changes
   - Rate limiting
   - Network issues

2. **Operational**
   - User adoption
   - Support requirements
   - Maintenance needs

## Success Metrics

1. **Quantitative**
   - Reduced manual work hours
   - Success rate
   - Processing time

2. **Qualitative**
   - User satisfaction
   - Error reduction
   - Support tickets

## Project Owner
Luke/Brian

## Problem Statement
Directly set the StrongAuthenticationPhoneNumber in Azure AD from Workday.

## Assumptions and Dependencies
- Workday has phone numbers available for Team Members.
- Consent and data privacy approvals are in place for using personal phone numbers as an authentication factor.
- Ongoing collaboration with HR/Workday for data feed maintenance and changes.
- Access to Workday API, Microsoft Graph API, and Secret Server.

## Stakeholders
- IAM Team: Luke/Brian
- Security: Bob/BrandonF
- HRIS/Workday: Amber? Manju? Sathish?
- Executive Sponsor: Justin Zimmerman

## Budget
- iPaaS (potential future integration point, currently direct API calls used)
- Continued licensing for Azure P1.

## Regulatory Drivers
- Ensure personal phone numbers are only used for MFA configuration and are not exposed in AD/Azure beyond the StrongAuthenticationPhoneNumber attribute.
- Improved security posture with Retail team members being enrolled into MFA by default.

## Return on Investment
- Reduce calls into the help desk from new onboards.
- Faster/Seamless onboarding for remote new employees.
- Universal MFA adoption.
- Operational efficiency to eliminate manual effort and opportunity to utilize this process to enhance corporate onboarding. 