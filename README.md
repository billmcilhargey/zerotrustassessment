[![PSGallery Version](https://img.shields.io/powershellgallery/v/ZeroTrustAssessment.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/ZeroTrustAssessment) 
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/ZeroTrustAssessment.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/ZeroTrustAssessment)

# Zero Trust Assessment

The Zero Trust Assessment is a PowerShell module that checks your tenant configuration and recommends ways to improve the security configuration.

To learn more see [aka.ms/zerotrust/assessment](https://aka.ms/zerotrust/assessment)

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.4 or later ([install guide](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)) |
| **OS** | Windows, macOS, or Linux (including GitHub Codespaces / dev containers) |
| **Entra ID role** | Global Reader (minimum) or Global Administrator |

## Quick start

### Option 1 — PSGallery (recommended)

```powershell
Install-PSResource -Name ZeroTrustAssessment -Scope CurrentUser
Start-ZtAssessment    # Interactive menu — connect, assess, view report
```

Or non-interactive:

```powershell
Connect-ZtAssessment
Invoke-ZtAssessment
```

See [Installing, updating, and running](#installing-updating-and-running) for update commands,
version pinning, run options, and report details.

### Option 2 — Developer / contributor workflow (from source)

A bash launcher is included for Linux, macOS, and Codespaces environments. It auto-installs
PowerShell if needed, imports the module from source, and provides an interactive developer
menu with Pester tests, service metadata auditing, report viewing, and planned test previews.

```bash
# Interactive developer menu
./invoke-ztdev.sh

# Direct actions
./invoke-ztdev.sh -Action Pester
./invoke-ztdev.sh -Action RunAll
./invoke-ztdev.sh -Action ViewReport
./invoke-ztdev.sh -Action UpdateTestServices
```

On Windows, run the PowerShell script directly:

```powershell
./Invoke-ZtDev.ps1
./Invoke-ZtDev.ps1 -Action RunAll
```

> **Tip:** Token caching is enabled by default — cached authentication tokens are
> reused across sessions so you don't need to re-authenticate each time. To disable
> token caching (require fresh auth each time), pass `-UseTokenCache:$false`.

After running an assessment, select **[V] View last assessment report** from the dev menu
(or use `-Action ViewReport`) to re-open the HTML report without re-running the assessment.
In Codespaces an HTTP server is started on port 8080 and the report opens automatically.

### Workshop documentation site

The `src/react/` folder contains a Docusaurus site with workshop guidance, pillar-specific
recommendations, videos, and FAQs in 11 languages. It starts automatically on port 3000
in the dev container:

```bash
cd src/react && npm run start
```

---

## Installing, updating, and running

### Install from PowerShell Gallery

```powershell
Install-PSResource -Name ZeroTrustAssessment -Scope CurrentUser
```

### Update to the latest version

```powershell
Update-PSResource -Name ZeroTrustAssessment -Scope CurrentUser
```

### Install a specific version

```powershell
Install-PSResource -Name ZeroTrustAssessment -Version 2.1.8 -Scope CurrentUser
```

Preview builds are tagged with a prerelease label (e.g. `2.1.8-preview`):

```powershell
Install-PSResource -Name ZeroTrustAssessment -Prerelease -Scope CurrentUser
```

### Uninstall

```powershell
# Remove the module
Uninstall-PSResource -Name ZeroTrustAssessment -Scope CurrentUser

# Remove saved configuration (ClientId, TenantId, etc.)
Get-PSFConfig -Module ZeroTrustAssessment | Unregister-PSFConfig

# Remove cached authentication tokens
Remove-Item -Path (Join-Path $HOME '.token-cache') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path (Split-Path (Get-Module Microsoft.Graph.Authentication -ListAvailable | Select-Object -First 1).Path) 'msal_*_cache.*') -Force -ErrorAction SilentlyContinue

# Delete assessment output (if still present)
Remove-Item -Path ./ZeroTrustReport -Recurse -Force -ErrorAction SilentlyContinue
```

> **Note:** The module itself does not modify your tenant. Only local files (config, tokens, report output) are created. The DuckDB native library is stored inside the module folder and is removed automatically by `Uninstall-PSResource`. The `PSFramework` dependency module remains installed (it may be used by other modules).

### Run the assessment

```powershell
Connect-ZtAssessment      # Authenticate and connect services
Invoke-ZtAssessment       # Export data, run tests, generate report
```

### What happens when you run it

Once `Invoke-ZtAssessment` starts, the module executes five stages automatically:

| Stage | What happens | Typical duration |
|-------|-------------|-----------------|
| **1. Pre-flight checks** | Validates PowerShell language mode, DuckDB engine, Graph context (scopes + roles), service health, and service coverage. Warns about tests that will be skipped due to missing services. | Seconds |
| **2. Export tenant data** | Reads configuration data from Microsoft Graph, Azure, Exchange Online, Security & Compliance, SharePoint Online, and AIPService in parallel. Exports JSON files to the `zt-export/` folder. | 5–30 min |
| **3. Build local database** | Loads the exported JSON into a local DuckDB database (`zt-export/db/zt.db`) for fast cross-referencing during tests. | Seconds |
| **4. Run assessment tests** | Evaluates ~269 Zero Trust checks in parallel across all pillars (Identity, Devices, Network, Data, Infrastructure, Visibility/Automation/Orchestration). Each test queries the local database and returns a pass/fail/skip result with remediation guidance. | 5–15 min |
| **5. Generate report** | Produces a single-file interactive HTML report (`ZeroTrustAssessmentReport.html`) with a risk dashboard, per-test results, and links to relevant Microsoft Learn documentation. Automatically opens in your browser. | Seconds |

After completion, the module warns you to delete the `zt-export/` folder since it contains sensitive tenant configuration data.

### Common options

```powershell
# Assess a single pillar
Invoke-ZtAssessment -Pillar Identity

# Resume after a timeout (reuses previously exported data)
Invoke-ZtAssessment -Resume

# Run specific tests by ID
Invoke-ZtAssessment -Tests 25392, 35001

# Set a custom output path
Invoke-ZtAssessment -Path ./my-report

# Load options from a JSON configuration file
Invoke-ZtAssessment -ConfigurationFile ./zt-config.json

# Include debug logs for troubleshooting
Invoke-ZtAssessment -ExportLog
```

### Report output

The assessment produces the following files:

```
./ZeroTrustReport/
├── ZeroTrustAssessmentReport.html   ← Interactive HTML dashboard (open in browser)
└── zt-export/
    ├── *.json                        ← Raw tenant data exports
    ├── db/zt.db                      ← Local DuckDB query cache
    └── ZeroTrustAssessmentReport.json ← Machine-readable test results
```

> **Important:** Delete the `zt-export/` folder after reviewing the report. It contains sensitive configuration data from your tenant.

---

## Enterprise Application registration

By default, `Connect-ZtAssessment` uses the built-in Microsoft Graph PowerShell application and
prompts each user interactively for consent. This works fine for ad-hoc assessments, but
registering your own **Enterprise Application (app registration)** in Microsoft Entra ID provides
significant advantages for organizations that run assessments regularly or in automated pipelines.

### Why register an Enterprise Application?

| Benefit | Details |
|---------|---------|
| **One-time admin consent** | A Global Administrator grants the required permissions once. After that, any authorized user or automation can run the assessment without seeing consent prompts. |
| **No interactive sign-in required** | App-only auth (certificate, client secret, managed identity) runs unattended — ideal for CI/CD, Azure Automation, scheduled tasks, and headless Linux servers. |
| **Scoped and auditable** | The app registration is a named, trackable identity in your tenant. You control exactly which permissions it has, who can use it, and you can review sign-in logs in Entra ID. |
| **Token caching not needed** | App-only authentication uses client credentials, eliminating dependency on user token caches and interactive browser sessions. |
| **Centralized control** | Revoke access instantly by disabling the Enterprise Application or removing its credentials — no need to change individual user permissions. |
| **Conditional Access support** | Apply Conditional Access policies (location, device compliance, risk) to the service principal, giving you the same Zero Trust controls over the assessment tool itself. |

### How permissions work

When you grant admin consent to the Enterprise Application, the permissions are approved at the
tenant level. This means:

- **No per-user consent pop-ups** — the app already has the permissions it needs.
- **Users don't need Global Reader** — the service principal reads data on their behalf using
  Application permissions (not Delegated). However, you still control who can *run* the
  PowerShell script through RBAC or access policies.
- **The PowerShell module connects immediately** — once `Connect-ZtAssessment` authenticates
  with the app's credentials, it has all required scopes and the assessment starts without
  further prompts.

### Step-by-step setup

#### 1. Create the app registration

In the [Microsoft Entra admin center](https://entra.microsoft.com):

1. Go to **Identity** → **Applications** → **App registrations** → **New registration**.
2. Name it something recognizable (e.g. `Zero Trust Assessment`).
3. Set **Supported account types** to *Accounts in this organizational directory only*.
4. No redirect URI is needed for app-only auth. Click **Register**.
5. Copy the **Application (client) ID** and **Directory (tenant) ID** — you'll need them below.

#### 2. Add API permissions

On the app registration's **API permissions** page, add the following **Application permissions**
(not Delegated) for **Microsoft Graph**:

| Permission | Type | Description |
|-----------|------|-------------|
| `AuditLog.Read.All` | Application | Read audit log data |
| `CrossTenantInformation.ReadBasic.All` | Application | Read cross-tenant basic info |
| `DeviceManagementApps.Read.All` | Application | Read Intune app config |
| `DeviceManagementConfiguration.Read.All` | Application | Read Intune device config |
| `DeviceManagementManagedDevices.Read.All` | Application | Read managed devices |
| `DeviceManagementRBAC.Read.All` | Application | Read Intune RBAC settings |
| `DeviceManagementServiceConfig.Read.All` | Application | Read Intune service config |
| `Directory.Read.All` | Application | Read directory data |
| `DirectoryRecommendations.Read.All` | Application | Read Entra recommendations |
| `EntitlementManagement.Read.All` | Application | Read entitlement management |
| `IdentityRiskEvent.Read.All` | Application | Read risk events |
| `IdentityRiskyServicePrincipal.Read.All` | Application | Read risky service principals |
| `IdentityRiskyUser.Read.All` | Application | Read risky users |
| `NetworkAccess.Read.All` | Application | Read network access config |
| `Policy.Read.All` | Application | Read all policies |
| `Policy.Read.ConditionalAccess` | Application | Read Conditional Access policies |
| `Policy.Read.PermissionGrant` | Application | Read permission grant policies |
| `PrivilegedAccess.Read.AzureAD` | Application | Read PIM role settings |
| `Reports.Read.All` | Application | Read usage reports |
| `RoleManagement.Read.All` | Application | Read role definitions and assignments |
| `UserAuthenticationMethod.Read.All` | Application | Read user auth methods |

> **Tip:** All 21 permissions are **read-only**. The assessment never modifies your tenant. Run
> `Get-ZtGraphScope` at any time to see the current list programmatically.

#### 3. Grant admin consent

Click **Grant admin consent for \<your tenant\>** and confirm. The status column should show
a green check for every permission.

#### 4. Create a credential

Choose **one** of the following based on your scenario:

**Certificate (recommended for production)**

1. On the app registration's **Certificates & secrets** → **Certificates** tab, upload the
   public key (`.cer` / `.pem`).
2. Install the private key on the machine that will run the assessment.

**Client secret (simpler, less secure)**

1. On the **Certificates & secrets** → **Client secrets** tab, create a new secret.
2. Copy the secret value immediately (it won't be shown again).
3. Store it securely (e.g. Azure Key Vault, CI/CD secret variable).

**Managed identity (Azure-hosted only)**

No credential needed. Assign the required Graph Application permissions to the managed identity
using PowerShell:

```powershell
# Example: grant permissions to a system-assigned managed identity
$miObjectId = (Get-AzADServicePrincipal -DisplayName 'my-automation-account').Id
$graphSp = Get-AzADServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

foreach ($scope in (Get-ZtGraphScope)) {
    $role = $graphSp.AppRole | Where-Object Value -eq $scope
    New-AzADServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $miObjectId `
        -ResourceId $graphSp.Id `
        -AppRoleId $role.Id
}
```

#### 5. Connect using the Enterprise Application

```powershell
# Certificate (recommended)
Connect-ZtAssessment -ClientId '<app-id>' -TenantId '<tenant-id>' -Certificate 'CN=ZeroTrustAssessment'

# Certificate thumbprint
Connect-ZtAssessment -ClientId '<app-id>' -TenantId '<tenant-id>' -CertificateThumbprint 'A1B2C3D4...'

# Client secret
$secret = $env:ZT_CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force
Connect-ZtAssessment -ClientId '<app-id>' -TenantId '<tenant-id>' -ClientSecret $secret

# Managed identity (system-assigned)
Connect-ZtAssessment -ManagedIdentity

# Managed identity (user-assigned)
Connect-ZtAssessment -ManagedIdentity -ClientId '<user-assigned-mi-client-id>'
```

Once authenticated, `Invoke-ZtAssessment` runs immediately — no consent prompts, no browser
pop-ups, no role checks. The Enterprise Application's pre-approved permissions are used
directly.

### Save default connection settings

To avoid passing `-ClientId` and `-TenantId` every time, save them as module defaults:

```powershell
Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.ClientId' -Value '<app-id>' -PassThru | Register-PSFConfig
Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.TenantId' -Value '<tenant-id>' -PassThru | Register-PSFConfig
```

Now `Connect-ZtAssessment -Certificate 'CN=ZeroTrustAssessment'` picks up the IDs automatically.

### Interactive vs. Enterprise Application — comparison

| Capability | Interactive (default) | Enterprise Application |
|-----------|:--------------------:|:---------------------:|
| Consent required per user | Yes (first run) | No (admin grants once) |
| Runs unattended | No | Yes |
| Works in CI/CD pipelines | No | Yes |
| Works in Azure Automation | No | Yes |
| Auditable service principal in Entra | No | Yes |
| Conditional Access on the tool itself | No | Yes |
| Requires Global Reader role for user | Yes | No (app has its own permissions) |
| Setup effort | None | One-time (10 min) |

### Required permissions for other services

The Graph permissions above cover the majority of tests. If you connect to additional services,
the Enterprise Application (or the user running the assessment) also needs:

| Service | Requirement | Notes |
|---------|------------|-------|
| **Azure (Az)** | Reader role on subscriptions | For Azure resource policy checks |
| **Exchange Online** | View-Only Organization Management (or Global Reader) | For mail flow and org config checks |
| **Security & Compliance** | Compliance Administrator (or Global Reader) | For DLP, retention, and sensitivity label checks |
| **SharePoint Online** | SharePoint Administrator | For SharePoint/OneDrive configuration checks |
| **Azure Information Protection** | Global Reader | For AIP label and policy checks (Windows only) |

---

## Cross-Platform Support

The assessment runs on **any platform** that supports PowerShell 7. Most tests (~98%) work identically across all platforms. A small number of tests require Windows-only PowerShell modules and are automatically skipped on non-Windows systems.

### Service compatibility

| Service | Windows | macOS | Linux / Codespaces | Module |
|---------|:-------:|:-----:|:------------------:|--------|
| **Microsoft Graph** | ✅ | ✅ | ✅ | `Microsoft.Graph.Authentication` |
| **Azure (Az)** | ✅ | ✅ | ✅ | `Az.Accounts` |
| **Exchange Online** | ✅ | ✅ | ✅ | `ExchangeOnlineManagement` |
| **Security & Compliance** | ✅ | ✅ | ✅ | `ExchangeOnlineManagement` |
| **Azure Information Protection** | ✅ | ❌ | ❌ | `AIPService` (Windows only) |
| **SharePoint Online** | ✅ | ✅ | ✅ | `PnP.PowerShell` |

### Impact on test coverage

| Platform | Tests available | Tests skipped | Skipped tests |
|----------|:--------------:|:-------------:|---------------|
| **Windows** | 269 / 269 | 0 | — |
| **macOS / Linux** | 268 / 269 | 1 | 35011 (AIPService) |

> **Note:** The 1 skipped test is in the **Data** pillar. All other pillars (Identity, Devices, Infrastructure, Network, Visibility/Automation/Orchestration) have full cross-platform coverage.

### Authentication

| Method | Windows | macOS | Linux / Codespaces |
|--------|:-------:|:-----:|:------------------:|
| Interactive browser (SSO) | ✅ | ✅ | ❌ (no browser) |
| Device code flow | ✅ | ✅ | ✅ (auto-enabled) |
| Certificate / app identity | ✅ | ✅ | ✅ |
| Client secret / app identity | ✅ | ✅ | ✅ |
| Managed identity (Azure-hosted) | ✅ | ✅ | ✅ |
| Token cache (persistent auth) | ✅ (default) | ✅ (default) | ✅ (default) |

Token caching is enabled by default on all platforms — cached tokens persist across PowerShell sessions, so you won't need to re-authenticate when resuming after a timeout. To disable, pass `-UseTokenCache:$false`. In Codespaces and headless environments, device-code authentication is also enabled automatically.

---

## Quicklinks

* [aka.ms/zerotrust/assessment](https://aka.ms/zerotrust/assessment) → Microsoft Learn docs page for the assessment (includes install guide).
* [aka.ms/zerotrust/demo](https://aka.ms/zerotrust/demo) → Interactive demo of a sample assessment report.
* [aka.ms/zerotrust/feedback](https://aka.ms/zerotrust/feedback) → Share your feedback. Let us know what you like and how we can improve.
* [aka.ms/zerotrust/issues](https://aka.ms/zerotrust/issues) → Logging bugs & issues

## Zero Trust Assessment Report

Sample report generated by the Zero Trust Assessment tool. Try [aka.ms/zerotrust/demo](https://aka.ms/zerotrust/demo) for an interactive demo.

![ZeroTrustAssessmentReport](https://github.com/user-attachments/assets/929b3ea6-7e54-47ce-9626-9adddee5fd2f)

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details on how to contribute to this project.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
