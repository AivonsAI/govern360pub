<#
.SYNOPSIS
    Govern360 by AIVONS - Pre-POC readiness check. READ-ONLY.

.DESCRIPTION
    Run this before a Govern360 proof of concept. It checks, module by module,
    what access and data your Microsoft organisation has for Govern360, and
    writes ONE self-contained HTML report plus a JSON file of the same results.

    READ-ONLY GUARANTEE
      - Every call is a read (HTTP GET). The only exception is the Azure Cost
        Management "query" API, which Microsoft exposes as a POST but which
        only reads a 7-day cost total; it is marked READ-ONLY QUERY below.
      - It creates nothing in your tenant: no app registrations, no service
        principals, no secrets, no role assignments, no consent grants, no
        setting changes.
      - Access tokens stay in memory, are never printed, logged or saved, and
        are cleared when the run ends.
      - The report holds counts, role names and the names of environments,
        capacities and subscriptions. It never holds user names from usage
        reports, secret values, or any content.

    Signing in: Microsoft Graph PowerShell may ask YOU to consent to its own
    delegated read scopes the first time it is used in your tenant. That is
    Microsoft's sign-in for its own PowerShell app, not a Govern360 grant.
    Leave "Consent on behalf of your organization" unticked.

.PARAMETER TenantId
    Directory (tenant) id to check. Defaults to the tenant you are signed in to.
.PARAMETER OutputPath
    Folder for the report, or a full .html file path. Default: the current
    folder (in Azure Cloud Shell: $HOME/clouddrive when it exists).
.PARAMETER NoInstall
    Never install PowerShell modules. Missing modules only mark checks as not checked.
.PARAMETER IncludePurview
    Also open a read-only Security & Compliance PowerShell session and count
    DLP policies (Get-DlpCompliancePolicy). Needs ExchangeOnlineManagement.
.PARAMETER SkipIntune
    Do not request DeviceManagementManagedDevices.Read.All and skip the device check.
.PARAMETER SkipDataverse
    Do not count Copilot Studio agents inside Dataverse environments.
.PARAMETER UseDeviceCode
    Sign in to Microsoft Graph with a device code (default in Azure Cloud Shell).
.PARAMETER MaxSubscriptions
    Maximum Azure subscriptions to inspect (default 25).
.PARAMETER MaxDataverseEnvironments
    Maximum Dataverse environments to count agents in (default 5).
.PARAMETER TimeoutSec
    Timeout for each web request (default 60).

.EXAMPLE
    ./Govern360-PrePOC-Readiness.ps1
.EXAMPLE
    ./Govern360-PrePOC-Readiness.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -OutputPath C:\Temp -NoInstall

.NOTES
    Govern360 by AIVONS. Works on Windows PowerShell 5.1 and PowerShell 7+.
    Exit code is 0 even when items are missing - the report is the result.
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath,
    [switch]$NoInstall,
    [switch]$IncludePurview,
    [switch]$SkipIntune,
    [switch]$SkipDataverse,
    [switch]$UseDeviceCode,
    [int]$MaxSubscriptions = 25,
    [int]$MaxDataverseEnvironments = 5,
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$G360ToolVersion = '1.0.0'
$G360RunStart = Get-Date

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'TLS setting unchanged.' }

# ---------------------------------------------------------------------------
# What Govern360 asks for. Mirrors the Govern360 console (microsoftModules.js):
# ONE Entra app "Govern360 (read-only)" holding Microsoft Graph APPLICATION
# permissions, granted in one admin-consent pass.
# ---------------------------------------------------------------------------
$G360AppName = 'Govern360 (read-only)'
$GraphAppId = '00000003-0000-0000-c000-000000000000'

$MsModules = @(
    @{ id = 'purview'; label = 'Purview / DLP'; defaultOn = $true; scopes = @('SecurityAlert.Read.All') },
    @{ id = 'conditional_access'; label = 'Conditional Access'; defaultOn = $true; scopes = @('Policy.Read.All') },
    @{ id = 'identity'; label = 'Identity & groups'; defaultOn = $true; scopes = @('Group.Read.All', 'Directory.Read.All') },
    @{ id = 'device_posture'; label = 'Device posture'; defaultOn = $true; scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All') },
    @{ id = 'm365_trust'; label = 'Microsoft 365 Trust'; defaultOn = $true; scopes = @('SecurityEvents.Read.All', 'Reports.Read.All', 'Sites.Read.All', 'AuditLog.Read.All', 'Application.Read.All') },
    @{ id = 'ai_email_discovery'; label = 'AI signup email discovery'; defaultOn = $false; scopes = @('User.Read.All', 'Mail.Read') },
    @{ id = 'agent_registry'; label = 'Agent Registry (Agent 365)'; defaultOn = $false; scopes = @('CopilotPackages.Read.All') },
    @{ id = 'agent_activity'; label = 'Agent run activity'; defaultOn = $false; scopes = @('AuditLogsQuery.Read.All') },
    @{ id = 'copilot_prompts'; label = 'Copilot prompts and answers'; defaultOn = $false; scopes = @('AiEnterpriseInteraction.Read.All') },
    @{ id = 'global_secure_access'; label = 'Global Secure Access'; defaultOn = $false; scopes = @('NetworkAccess-Reports.Read.All') }
)

$ScopeHelp = @{
    'SecurityAlert.Read.All'                  = 'Read security/DLP alerts (Purview DLP signals).'
    'Policy.Read.All'                         = 'Read Conditional Access and other policies (read-only).'
    'Group.Read.All'                          = 'Read Entra groups so policies can target them.'
    'Directory.Read.All'                      = 'Resolve group membership and user attribution.'
    'DeviceManagementManagedDevices.Read.All' = 'Read managed-device posture for deployment validation.'
    'DeviceManagementConfiguration.Read.All'  = 'Read Intune configuration and compliance policies (read-only).'
    'SecurityEvents.Read.All'                 = 'Read security events for the M365 trust posture.'
    'Reports.Read.All'                        = 'Read usage/adoption and license reports.'
    'Sites.Read.All'                          = 'Read SharePoint/OneDrive site metadata for exposure analysis.'
    'AuditLog.Read.All'                       = 'Read the unified audit log for activity evidence.'
    'Application.Read.All'                    = 'Read app registrations and service principals inventory.'
    'User.Read.All'                           = 'Read the user directory to enumerate mailboxes for the email scan.'
    'Mail.Read'                               = 'Read mail metadata to detect AI-vendor signup emails (vendor + date only).'
    'CopilotPackages.Read.All'                = 'Read the tenant agent catalog (ISV and Microsoft agents). Needs Agent 365.'
    'AuditLogsQuery.Read.All'                 = 'Read Copilot Studio agent runs from the Purview audit log (all audit workloads).'
    'AiEnterpriseInteraction.Read.All'        = 'Read Microsoft 365 Copilot prompts and answers for your detectors; only findings are kept.'
    'NetworkAccess-Reports.Read.All'          = 'Read the Global Secure Access traffic log (apps reached, allowed or blocked).'
}

$DefaultScopes = @()
foreach ($m in $MsModules) { if ($m.defaultOn) { foreach ($scp in $m.scopes) { if ($DefaultScopes -notcontains $scp) { $DefaultScopes += $scp } } } }
$DefaultScopes = @($DefaultScopes | Sort-Object)

# Entra directory roles this check looks for (well-known template ids).
$RoleCatalog = @(
    @{ key = 'GA'; name = 'Global Administrator'; id = '62e90394-69f5-4237-9190-012177145e10'; why = 'Grants tenant-wide admin consent for the Govern360 Graph application permissions.' },
    @{ key = 'PRA'; name = 'Privileged Role Administrator'; id = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; why = 'Can also grant admin consent for Graph application permissions.' },
    @{ key = 'AppAdmin'; name = 'Application Administrator'; id = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; why = 'Can create the Govern360 app registration (cannot consent to Graph application permissions).' },
    @{ key = 'CloudAppAdmin'; name = 'Cloud Application Administrator'; id = '158c047a-c907-4556-b7ef-446551a6b5f7'; why = 'Can create the Govern360 app registration (cannot consent to Graph application permissions).' },
    @{ key = 'SecAdmin'; name = 'Security Administrator'; id = '194ae4cb-b126-40b2-bd5b-6091b380977d'; why = 'Defender and Purview alert configuration.' },
    @{ key = 'SecReader'; name = 'Security Reader'; id = '5d6b6bb7-de71-4623-b4af-96380a352509'; why = 'Read Defender and Purview alerts and Secure Score.' },
    @{ key = 'GlobalReader'; name = 'Global Reader'; id = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'; why = 'Read-only view across admin centres, useful for these checks.' },
    @{ key = 'ComplianceAdmin'; name = 'Compliance Administrator'; id = '17315797-102d-40b4-93e0-432062caca18'; why = 'Purview DLP policies, audit and sensitivity labels.' },
    @{ key = 'PPAdmin'; name = 'Power Platform Administrator'; id = '11648597-926c-4cf3-9c36-bcebb0ba8dcc'; why = 'Consents the Power Platform connection, registers the management app, adds application users.' },
    @{ key = 'FabricAdmin'; name = 'Fabric Administrator'; id = 'a9ea8996-122f-4c74-9520-8edcd192826c'; why = 'Enables the Fabric tenant settings for service principals.' },
    @{ key = 'IntuneAdmin'; name = 'Intune Administrator'; id = '3a2c62db-5318-420d-8d74-23affee5d9d5'; why = 'Device posture and Intune policy read-back.' },
    @{ key = 'ReportsReader'; name = 'Reports Reader'; id = '4a5d8f65-41da-4de4-8968-e035b65339cf'; why = 'Microsoft 365 usage reports, including Copilot usage.' },
    @{ key = 'BillingAdmin'; name = 'Billing Administrator'; id = 'b0f54661-2d74-4c50-afa3-1ec803f12efe'; why = 'Licences and Microsoft 365 subscriptions.' }
)

# Azure built-in role definition ids (well-known).
$AzRoleNames = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
    '72fafb9e-0641-4937-9268-a91bfd8191a3' = 'Cost Management Reader'
    '434105ed-43f6-45c7-a02f-909b2ba83430' = 'Cost Management Contributor'
    'fa23ad8b-c56e-40d8-ac0c-ce449e1d2c64' = 'Billing Reader'
    '39bc4728-0917-49c7-9d2c-d95423bc2eb4' = 'Security Reader'
}

$ModuleDefs = @(
    @{ key = 'admin'; n = 1; label = 'Signed-in admin and tenant'; sub = 'Who ran this and what they can approve' },
    @{ key = 'entra'; n = 2; label = 'Microsoft Entra connection'; sub = 'The Govern360 (read-only) app and its Microsoft Graph permissions' },
    @{ key = 'licences'; n = 3; label = 'Licences'; sub = 'Copilot, E3/E5, Entra ID, Intune, Purview, Power Platform, Fabric' },
    @{ key = 'copilot'; n = 4; label = 'Microsoft 365 Copilot seats and usage report'; sub = 'Copilot Consumption' },
    @{ key = 'powerplatform'; n = 5; label = 'Power Platform and Copilot Studio'; sub = 'Agent inventory and Copilot Credits' },
    @{ key = 'azure'; n = 6; label = 'Azure (Azure OpenAI and AI Services)'; sub = 'Subscriptions, AI resources and Cost Management' },
    @{ key = 'fabric'; n = 7; label = 'Microsoft Fabric'; sub = 'Capacities and service principal tenant settings' },
    @{ key = 'purview'; n = 8; label = 'Purview and compliance'; sub = 'Purview / DLP alerts, labels and DLP policies' },
    @{ key = 'intune'; n = 9; label = 'Device posture (Intune)'; sub = 'Managed devices by operating system' },
    @{ key = 'identity'; n = 10; label = 'Identity & groups and Conditional Access'; sub = 'Entra identity signals' }
)

# ---------------------------------------------------------------------------
# State. $S is shared by every check (hashtable = reference, safe in child scopes).
# ---------------------------------------------------------------------------
$S = @{
    GraphMode = 'none'; GraphScopes = @(); ConnectedGraph = $false
    AzReady = $false; MeId = $null; Upn = $null; TenantId = $TenantId; Domain = $null; InitialDomain = $null; OrgName = $null
    ActiveRoles = @(); EligibleRoles = @(); EligibleRead = $false; RolesRead = $false
    G360Sps = @(); MainSp = $null; GrantedGraph = @(); EntraRead = $false; PbiPermsOnG360 = 0
    Lic = @{}; LicRead = $false
    FabricArmCount = 0; FabricArmNames = @()
    TokenCache = @{}
}
$Results = New-Object System.Collections.ArrayList
$Actions = New-Object System.Collections.ArrayList
$Tables = New-Object System.Collections.ArrayList
$ModuleState = @{}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-G360Step {
    param([int]$Number, [string]$Text)
    Write-Host ''
    Write-Host ('[{0}/10] {1}' -f $Number, $Text) -ForegroundColor Cyan
}

function Write-G360Line {
    param([string]$Status, [string]$Text)
    $color = 'Gray'; $tag = $Status
    switch ($Status) {
        'ok' { $color = 'Green'; $tag = 'OK' }
        'warning' { $color = 'Yellow'; $tag = 'WARNING' }
        'missing' { $color = 'Red'; $tag = 'MISSING' }
        'not_checked' { $color = 'DarkGray'; $tag = 'NOT CHECKED' }
    }
    Write-Host ('    {0,-12} {1}' -f $tag, $Text) -ForegroundColor $color
}

function Add-G360Result {
    param([string]$Module, [string]$Check, [string]$Status, [string]$Detail, [string]$FixRole)
    $o = [pscustomobject]@{ module = $Module; check = $Check; status = $Status; detail = (Protect-G360Text $Detail); who_can_fix = $FixRole }
    [void]$Results.Add($o)
    Write-G360Line $Status ($Check + ': ' + $o.detail)
}

function Add-G360Action {
    param([string]$Module, [string]$Text, [string]$Role, [int]$Priority = 2)
    foreach ($a in $Actions) { if ($a.text -eq $Text) { return } }
    [void]$Actions.Add([pscustomobject]@{ module = $Module; text = $Text; role = $Role; priority = $Priority })
}

function Add-G360Table {
    param([string]$Module, [string]$Title, [string[]]$Columns, [object[]]$Rows, [string]$Note)
    [void]$Tables.Add([pscustomobject]@{ module = $Module; title = $Title; columns = $Columns; rows = $Rows; note = $Note })
}

function Set-G360Module {
    param([string]$Key, [string]$Status, [string]$Summary)
    $ModuleState[$Key] = @{ status = $Status; summary = $Summary }
}

# Remove anything token-shaped from text that came back from a service.
function Protect-G360Text {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = [string]$Text
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*', '[redacted]')
    $t = [regex]::Replace($t, '(?i)bearer\s+[A-Za-z0-9\._\-]+', 'Bearer [redacted]')
    $t = [regex]::Replace($t, '\s+', ' ')
    return $t.Trim()
}

function Get-G360Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
}

function ConvertTo-G360Date {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    try {
        $st = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $st)
    } catch { return $null }
}

function Get-G360HttpStatus {
    param($ErrorRecord)
    $code = 0
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($null -ne $resp) { $code = [int]$resp.StatusCode }
    } catch { $code = 0 }
    if ($code -gt 0) { return $code }
    $txt = ''
    try { $txt = [string]$ErrorRecord.Exception.Message } catch { $txt = [string]$ErrorRecord }
    try { if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $txt = $txt + ' ' + $ErrorRecord.ErrorDetails.Message } } catch { Write-Verbose 'No error details.' }
    $m = [regex]::Match($txt, '\b(400|401|403|404|409|429|500|502|503|504)\b')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    if ($txt -match 'Authorization_RequestDenied|Forbidden|Insufficient privileges|AADSTS65001') { return 403 }
    if ($txt -match 'Unauthorized|InvalidAuthenticationToken') { return 401 }
    return 0
}

function Get-G360ErrorText {
    param($ErrorRecord)
    $m = ''
    try { if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $m = [string]$ErrorRecord.ErrorDetails.Message } } catch { $m = '' }
    if (-not $m) { try { $m = [string]$ErrorRecord.Exception.Message } catch { $m = [string]$ErrorRecord } }
    $j = [regex]::Match($m, '"message"\s*:\s*"([^"]{1,300})"')
    if ($j.Success) { $m = $j.Groups[1].Value }
    $trim = [regex]::Replace($m, '(?i)Response status code does not indicate success:\s*\d{3}\s*(\([^)]*\))?\.?\s*', '')
    if ($trim.Trim()) { $m = $trim }
    $m = Protect-G360Text $m
    if ($m.Length -gt 240) { $m = $m.Substring(0, 240) + '...' }
    return $m
}

function Get-G360DenyText {
    param($ErrorRecord, [string]$NeedRole)
    $code = Get-G360HttpStatus $ErrorRecord
    $msg = Get-G360ErrorText $ErrorRecord
    if ($code -eq 401 -or $code -eq 403) {
        $t = 'Microsoft refused the read (' + $code + ')'
        if ($NeedRole) { $t = $t + '; it needs ' + $NeedRole }
        return $t + '. ' + $msg
    }
    if ($code -eq 404) { return 'Not found (404). ' + $msg }
    if ($code -eq 429) { return 'Microsoft throttled the read (429); run again later. ' + $msg }
    if ($code -gt 0) { return 'The read failed (' + $code + '). ' + $msg }
    return 'The read failed: ' + $msg
}

function Invoke-G360Check {
    param([string]$Module, [string]$Name, [scriptblock]$Body)
    try { & $Body }
    catch {
        Add-G360Result $Module $Name 'not_checked' ('The check stopped with an error and was skipped: ' + (Get-G360ErrorText $_)) ''
    }
}

function Test-G360CloudShell {
    if ($env:AZUREPS_HOST_ENVIRONMENT -and ($env:AZUREPS_HOST_ENVIRONMENT -match 'cloud-shell')) { return $true }
    if ($env:ACC_CLOUD) { return $true }
    return $false
}

function Format-G360Number {
    param($Value)
    if ($null -eq $Value) { return '-' }
    try { return ([double]$Value).ToString('#,0', [Globalization.CultureInfo]::InvariantCulture) } catch { return [string]$Value }
}

# ---------------------------------------------------------------------------
# Tokens (Az). In memory only; never printed, logged or saved.
# ---------------------------------------------------------------------------
function Get-G360Token {
    param([string]$Resource)
    if ($S.TokenCache.ContainsKey($Resource)) { return $S.TokenCache[$Resource] }
    if (-not $S.AzReady) { throw 'Azure sign-in is not available, so no token for this service could be obtained.' }
    $p = @{ ResourceUrl = $Resource; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    $cmd = Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and $cmd.Parameters.ContainsKey('AsSecureString')) { $p['AsSecureString'] = $true }
    if ($S.TenantId -and $null -ne $cmd -and $cmd.Parameters.ContainsKey('TenantId')) { $p['TenantId'] = $S.TenantId }
    $t = Get-AzAccessToken @p
    $raw = Get-G360Prop $t 'Token'
    $plain = $null
    if ($raw -is [System.Security.SecureString]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($raw)
        try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    } else { $plain = [string]$raw }
    if (-not $plain) { throw 'Azure returned no token for this service.' }
    $S.TokenCache[$Resource] = $plain
    return $plain
}

# REST read. GET only; a POST must be flagged -ReadOnlyQuery (Cost Management query).
function Invoke-G360Rest {
    param([string]$Resource, [string]$Uri, [string]$Method = 'GET', $Body, [switch]$ReadOnlyQuery)
    if ($Method -ne 'GET' -and -not $ReadOnlyQuery) { throw 'Blocked: this script only reads.' }
    $tok = Get-G360Token $Resource
    $h = @{ Authorization = ('Bearer ' + $tok); Accept = 'application/json' }
    $p = @{ Method = $Method; Uri = ($Uri -replace ' ', '%20'); Headers = $h; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $p['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress); $p['ContentType'] = 'application/json' }
    $r = Invoke-RestMethod @p
    $h = $null; $tok = $null
    return $r
}

# REST list with paging (nextLink / continuationUri).
function Get-G360RestItems {
    param([string]$Resource, [string]$Uri, [int]$MaxPages = 20)
    $items = New-Object System.Collections.ArrayList
    $next = $Uri; $page = 0
    while ($next -and $page -lt $MaxPages) {
        $page++
        $r = Invoke-G360Rest -Resource $Resource -Uri $next
        foreach ($v in @(Get-G360Prop $r 'value')) { if ($null -ne $v) { [void]$items.Add($v) } }
        $next = Get-G360Prop $r 'nextLink'
        if (-not $next) { $next = Get-G360Prop $r 'continuationUri' }
        if (-not $next) { $next = Get-G360Prop $r '@odata.nextLink' }
    }
    return $items.ToArray()
}

# ---------------------------------------------------------------------------
# Microsoft Graph reads. GET only.
# ---------------------------------------------------------------------------
function Get-G360Graph {
    param([string]$Path, [switch]$Eventual)
    if ($S.GraphMode -eq 'none') { throw 'Microsoft Graph sign-in is not available.' }
    $uri = $Path
    if ($uri -notmatch '^https://') { $uri = 'https://graph.microsoft.com/' + $Path }
    $uri = $uri -replace ' ', '%20'
    if ($S.GraphMode -eq 'mg') {
        $p = @{ Method = 'GET'; Uri = $uri; ErrorAction = 'Stop' }
        if ($Eventual) { $p['Headers'] = @{ ConsistencyLevel = 'eventual' } }
        return Invoke-MgGraphRequest @p
    }
    $tok = Get-G360Token 'https://graph.microsoft.com'
    $h = @{ Authorization = ('Bearer ' + $tok) }
    if ($Eventual) { $h['ConsistencyLevel'] = 'eventual' }
    $r = Invoke-RestMethod -Method GET -Uri $uri -Headers $h -TimeoutSec $TimeoutSec -ErrorAction Stop
    $h = $null; $tok = $null
    return $r
}

function Get-G360GraphItems {
    param([string]$Path, [switch]$Eventual, [int]$MaxPages = 20)
    $items = New-Object System.Collections.ArrayList
    $next = $Path; $page = 0
    while ($next -and $page -lt $MaxPages) {
        $page++
        $r = Get-G360Graph -Path $next -Eventual:$Eventual
        foreach ($v in @(Get-G360Prop $r 'value')) { if ($null -ne $v) { [void]$items.Add($v) } }
        $next = Get-G360Prop $r '@odata.nextLink'
    }
    return $items.ToArray()
}

function Get-G360GraphCount {
    param([string]$Path)
    $r = Get-G360Graph -Path $Path -Eventual
    $m = [regex]::Match([string]$r, '\d+')
    if ($m.Success) { return [int]$m.Value }
    return $null
}

function Test-G360Role {
    param([string]$Key, [switch]$Eligible)
    $list = $S.ActiveRoles
    if ($Eligible) { $list = $S.EligibleRoles }
    return (@($list) -contains $Key)
}

function Get-G360RoleName {
    param([string]$Key)
    foreach ($r in $RoleCatalog) { if ($r.key -eq $Key) { return $r.name } }
    return $Key
}

# ===========================================================================
# 0. Banner, modules, sign-in
# ===========================================================================
Write-Host ''
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host ' Govern360 by AIVONS - Pre-POC readiness check' -ForegroundColor Cyan
Write-Host ' READ-ONLY: reads your tenant, changes nothing, saves no tokens.' -ForegroundColor Cyan
Write-Host '==================================================================' -ForegroundColor Cyan

$IsCloudShell = Test-G360CloudShell
$NeededModules = @('Az.Accounts', 'Az.Resources', 'Microsoft.Graph.Authentication')
$MissingModules = @()
foreach ($mn in $NeededModules) {
    $found = $null
    try { $found = @(Get-Module -ListAvailable -Name $mn -ErrorAction SilentlyContinue) } catch { $found = @() }
    if (@($found).Count -eq 0) { $MissingModules += $mn }
}
if (@($MissingModules).Count -gt 0) {
    Write-Host ''
    Write-Host 'These PowerShell modules are not installed:' -ForegroundColor Yellow
    foreach ($mn in $MissingModules) { Write-Host ('    Install-Module -Name {0} -Scope CurrentUser -Repository PSGallery' -f $mn) -ForegroundColor Yellow }
    if ($NoInstall) {
        Write-Host '-NoInstall was given: nothing will be installed. Checks that need them are marked not checked.' -ForegroundColor Yellow
    } else {
        $ans = Read-Host 'Install them now for your account only (-Scope CurrentUser)? [y/N]'
        if ($ans -match '^(y|yes)$') {
            foreach ($mn in $MissingModules) {
                try { Install-Module -Name $mn -Scope CurrentUser -Repository PSGallery -ErrorAction Stop; Write-Host ('    Installed ' + $mn) -ForegroundColor Green }
                catch { Write-Host ('    Could not install ' + $mn + ': ' + (Get-G360ErrorText $_)) -ForegroundColor Yellow }
            }
        } else {
            Write-Host 'Not installing. Checks that need them are marked not checked.' -ForegroundColor Yellow
        }
    }
}
foreach ($mn in $NeededModules) {
    try { Import-Module $mn -ErrorAction Stop -WarningAction SilentlyContinue } catch { Write-Verbose ('Module not loaded: ' + $mn) }
}

# --- Azure sign-in (reuse the existing context) ---
Write-Host ''
Write-Host '-> Azure sign-in (reusing your current session where possible)...'
if (Get-Command Get-AzContext -ErrorAction SilentlyContinue) {
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        $ctxTenant = $null
        if ($null -ne $ctx) { $ctxTenant = Get-G360Prop (Get-G360Prop $ctx 'Tenant') 'Id' }
        if ($null -eq $ctx -or ($TenantId -and $ctxTenant -ne $TenantId)) {
            $cp = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
            if ($TenantId) { $cp['TenantId'] = $TenantId }
            if ($UseDeviceCode) { $cp['UseDeviceAuthentication'] = $true }
            [void](Connect-AzAccount @cp)
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
        }
        if ($null -ne $ctx) {
            $S.AzReady = $true
            if (-not $S.TenantId) { $S.TenantId = Get-G360Prop (Get-G360Prop $ctx 'Tenant') 'Id' }
            if (-not $S.Upn) { $S.Upn = Get-G360Prop (Get-G360Prop $ctx 'Account') 'Id' }
            Write-Host '    Azure session ready.' -ForegroundColor Green
        }
    } catch { Write-Host ('    Azure sign-in failed: ' + (Get-G360ErrorText $_)) -ForegroundColor Yellow }
} else { Write-Host '    Az.Accounts is not available; Azure, Power Platform and Fabric checks will be skipped.' -ForegroundColor Yellow }

# --- Microsoft Graph sign-in (delegated READ scopes only) ---
Write-Host '-> Microsoft Graph sign-in (delegated read-only scopes)...'
$GraphReadScopes = @('User.Read', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All', 'Organization.Read.All', 'Reports.Read.All', 'ReportSettings.Read.All', 'Policy.Read.All')
if (-not $SkipIntune) { $GraphReadScopes += 'DeviceManagementManagedDevices.Read.All' }
if (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) {
    $reuse = $false
    try {
        $mg = Get-MgContext
        if ($null -ne $mg) {
            $have = @(Get-G360Prop $mg 'Scopes')
            $mgTenant = Get-G360Prop $mg 'TenantId'
            $allIn = $true
            foreach ($sc in $GraphReadScopes) { if ($have -notcontains $sc) { $allIn = $false } }
            if ($allIn -and ((-not $S.TenantId) -or ($mgTenant -eq $S.TenantId))) { $reuse = $true; $S.GraphScopes = $have }
        }
    } catch { $reuse = $false }
    if ($reuse) {
        $S.GraphMode = 'mg'
        Write-Host '    Reusing your existing Microsoft Graph session.' -ForegroundColor Green
    } else {
        $cmd = Get-Command Connect-MgGraph
        foreach ($attempt in @('full', 'minimal')) {
            if ($S.GraphMode -ne 'none') { break }
            $sc = $GraphReadScopes
            if ($attempt -eq 'minimal') { $sc = @('User.Read', 'Directory.Read.All') }
            $cp = @{ Scopes = $sc; ErrorAction = 'Stop' }
            if ($S.TenantId) { $cp['TenantId'] = $S.TenantId }
            if ($cmd.Parameters.ContainsKey('NoWelcome')) { $cp['NoWelcome'] = $true }
            if ($cmd.Parameters.ContainsKey('ContextScope')) { $cp['ContextScope'] = 'Process' }
            if ($UseDeviceCode -or $IsCloudShell) {
                if ($cmd.Parameters.ContainsKey('UseDeviceCode')) { $cp['UseDeviceCode'] = $true }
                elseif ($cmd.Parameters.ContainsKey('UseDeviceAuthentication')) { $cp['UseDeviceAuthentication'] = $true }
            }
            try {
                [void](Connect-MgGraph @cp)
                $S.GraphMode = 'mg'; $S.ConnectedGraph = $true; $S.GraphScopes = $sc
                Write-Host ('    Signed in to Microsoft Graph (' + $attempt + ' scope set).') -ForegroundColor Green
            } catch {
                Write-Host ('    Graph sign-in with the ' + $attempt + ' scope set failed: ' + (Get-G360ErrorText $_)) -ForegroundColor Yellow
            }
        }
    }
}
if ($S.GraphMode -eq 'none' -and $S.AzReady) {
    $S.GraphMode = 'az'
    Write-Host '    Falling back to Microsoft Graph through your Azure session (reads only).' -ForegroundColor Yellow
}
if ($S.GraphMode -eq 'mg' -and (Get-Command Set-MgRequestContext -ErrorAction SilentlyContinue)) {
    try { [void](Set-MgRequestContext -ClientTimeout $TimeoutSec -MaxRetry 2 -ErrorAction Stop) } catch { Write-Verbose 'Graph request timeout left at its default.' }
}

# ===========================================================================
# 1. Signed-in admin & tenant
# ===========================================================================
Write-G360Step 1 'Signed-in admin and tenant'
Invoke-G360Check 'admin' 'Signed-in account' {
    $me = Get-G360Graph 'v1.0/me?$select=id,userPrincipalName'
    $S.MeId = Get-G360Prop $me 'id'
    $S.Upn = Get-G360Prop $me 'userPrincipalName'
    Add-G360Result 'admin' 'Signed-in account' 'ok' ('Signed in as ' + $S.Upn + '.') ''
}
Invoke-G360Check 'admin' 'Tenant' {
    $org = @(Get-G360GraphItems 'v1.0/organization?$select=id,displayName,verifiedDomains')[0]
    $S.TenantId = Get-G360Prop $org 'id'
    $S.OrgName = Get-G360Prop $org 'displayName'
    foreach ($d in @(Get-G360Prop $org 'verifiedDomains')) {
        if (Get-G360Prop $d 'isDefault') { $S.Domain = Get-G360Prop $d 'name' }
        if (Get-G360Prop $d 'isInitial') { $S.InitialDomain = Get-G360Prop $d 'name' }
    }
    if (-not $S.Domain) { $S.Domain = $S.InitialDomain }
    Add-G360Result 'admin' 'Tenant' 'ok' ($S.OrgName + ' - tenant id ' + $S.TenantId + ', default domain ' + $S.Domain + '.') ''
}
Invoke-G360Check 'admin' 'Active directory roles' {
    $dr = @(Get-G360GraphItems 'v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName,roleTemplateId')
    $keys = @(); $names = @()
    foreach ($r in $dr) {
        $tid = Get-G360Prop $r 'roleTemplateId'; $dn = Get-G360Prop $r 'displayName'
        $names += $dn
        foreach ($c in $RoleCatalog) { if ($c.id -eq $tid -or $c.name -eq $dn) { $keys += $c.key } }
    }
    $S.ActiveRoles = $keys; $S.RolesRead = $true
    if (@($names).Count -gt 0) { Add-G360Result 'admin' 'Active directory roles' 'ok' (($names | Sort-Object) -join ', ') '' }
    else { Add-G360Result 'admin' 'Active directory roles' 'warning' 'No active Entra directory roles. Most checks below need at least Global Reader.' 'Privileged Role Administrator' }
}
Invoke-G360Check 'admin' 'PIM-eligible roles' {
    if (-not $S.MeId) { Add-G360Result 'admin' 'PIM-eligible roles' 'not_checked' 'The signed-in account could not be read, so eligible roles were not checked.' ''; return }
    try {
        $el = @(Get-G360GraphItems ("v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '" + $S.MeId + "'&`$expand=roleDefinition"))
        $keys = @(); $names = @()
        foreach ($e in $el) {
            $rd = Get-G360Prop $e 'roleDefinition'
            $tid = Get-G360Prop $rd 'templateId'; $dn = Get-G360Prop $rd 'displayName'
            $names += $dn
            foreach ($c in $RoleCatalog) { if ($c.id -eq $tid -or $c.name -eq $dn) { $keys += $c.key } }
        }
        $S.EligibleRoles = $keys; $S.EligibleRead = $true
        if (@($names).Count -gt 0) { Add-G360Result 'admin' 'PIM-eligible roles' 'ok' ('Eligible (activate in PIM before use): ' + (($names | Sort-Object) -join ', ')) '' }
        else { Add-G360Result 'admin' 'PIM-eligible roles' 'ok' 'No PIM-eligible roles for this account.' '' }
    } catch {
        Add-G360Result 'admin' 'PIM-eligible roles' 'not_checked' ((Get-G360DenyText $_ 'RoleManagement.Read.Directory and Entra ID P2 (PIM)') + ' Eligible roles are not shown.') ''
    }
}
Invoke-G360Check 'admin' 'Can grant admin consent' {
    if (-not $S.RolesRead) { Add-G360Result 'admin' 'Can grant admin consent' 'not_checked' 'Roles could not be read.' 'Global Administrator'; Set-G360Module 'admin' 'Not available' 'Directory roles could not be read.'; return }
    if ((Test-G360Role 'GA') -or (Test-G360Role 'PRA')) {
        Add-G360Result 'admin' 'Can grant admin consent' 'ok' ('Yes - ' + $S.Upn + ' can grant tenant-wide admin consent for the ' + @($DefaultScopes).Count + ' Microsoft Graph application permissions Govern360 requests.') ''
        Set-G360Module 'admin' 'Ready' 'This admin can grant tenant-wide admin consent.'
    } elseif ((Test-G360Role 'GA' -Eligible) -or (Test-G360Role 'PRA' -Eligible)) {
        Add-G360Result 'admin' 'Can grant admin consent' 'warning' 'Only after PIM activation: the account is eligible for Global Administrator or Privileged Role Administrator but it is not active now.' 'Global Administrator'
        Add-G360Action 'admin' 'Activate Global Administrator (or Privileged Role Administrator) in PIM before granting admin consent for Govern360' 'Global Administrator' 1
        Set-G360Module 'admin' 'Needs action' 'Can grant consent after PIM activation.'
    } else {
        Add-G360Result 'admin' 'Can grant admin consent' 'missing' 'No - granting admin consent for Microsoft Graph application permissions needs Global Administrator or Privileged Role Administrator. Application Administrator is not enough.' 'Global Administrator or Privileged Role Administrator'
        Add-G360Action 'admin' 'Have a Global Administrator (or Privileged Role Administrator) available to grant admin consent for Govern360' 'Global Administrator' 1
        Set-G360Module 'admin' 'Needs action' 'This admin cannot grant admin consent; a Global Administrator is needed.'
    }
}
$roleRows = @()
foreach ($c in $RoleCatalog) {
    $a = '-'; $e = '-'
    if (Test-G360Role $c.key) { $a = 'Yes' }
    if (Test-G360Role $c.key -Eligible) { $e = 'Yes' } elseif (-not $S.EligibleRead) { $e = 'not read' }
    $roleRows += , @($c.name, $a, $e, $c.why)
}
Add-G360Table 'admin' 'Directory roles of interest' @('Role', 'Active', 'PIM eligible', 'Why it matters for Govern360') $roleRows 'Active roles include roles held through role-assignable groups. PIM eligibility shows direct eligibility only.'
if (-not $ModuleState.ContainsKey('admin')) { Set-G360Module 'admin' 'Not available' 'The signed-in account could not be read.' }

# ===========================================================================
# 2. Microsoft Entra connection (Govern360 app)
# ===========================================================================
Write-G360Step 2 'Microsoft Entra connection (Govern360 app and Graph permissions)'
$G360Apps = @()
Invoke-G360Check 'entra' 'Govern360 app registration' {
    $apps = @(Get-G360GraphItems 'v1.0/applications?$search="displayName:Govern360"&$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess' -Eventual)
    $apps = @($apps | Where-Object { (Get-G360Prop $_ 'displayName') -match 'Govern360' })
    $sps = @(Get-G360GraphItems 'v1.0/servicePrincipals?$search="displayName:Govern360"&$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId' -Eventual)
    $sps = @($sps | Where-Object { (Get-G360Prop $_ 'displayName') -match 'Govern360' })
    $script:G360Apps = $apps
    $graphSp = Get-G360Graph ("v1.0/servicePrincipals(appId='" + $GraphAppId + "')?`$select=id,appRoles")
    $graphSpId = Get-G360Prop $graphSp 'id'
    $roleMap = @{}
    foreach ($ar in @(Get-G360Prop $graphSp 'appRoles')) { $roleMap[[string](Get-G360Prop $ar 'id')] = Get-G360Prop $ar 'value' }
    $list = @()
    foreach ($sp in $sps) {
        $spId = Get-G360Prop $sp 'id'
        $graphNames = @(); $pbi = 0; $other = @(); $deleg = @()
        try {
            foreach ($as in @(Get-G360GraphItems ('v1.0/servicePrincipals/' + $spId + '/appRoleAssignments'))) {
                $rid = [string](Get-G360Prop $as 'resourceId'); $rn = [string](Get-G360Prop $as 'resourceDisplayName')
                if ($rid -eq $graphSpId) { $v = $roleMap[[string](Get-G360Prop $as 'appRoleId')]; if ($v) { $graphNames += $v } }
                elseif ($rn -match 'Power BI|Fabric') { $pbi++ }
                else { $other += $rn }
            }
        } catch { Write-G360Line 'not_checked' ('Could not read granted permissions for ' + (Get-G360Prop $sp 'displayName') + ': ' + (Get-G360ErrorText $_)) }
        try {
            foreach ($g in @(Get-G360GraphItems ('v1.0/servicePrincipals/' + $spId + '/oauth2PermissionGrants'))) {
                foreach ($w in ([string](Get-G360Prop $g 'scope')).Split(' ')) { if ($w -and $deleg -notcontains $w) { $deleg += $w } }
            }
        } catch { Write-Verbose 'Delegated grants not read.' }
        $list += , @{ id = $spId; appId = (Get-G360Prop $sp 'appId'); name = (Get-G360Prop $sp 'displayName'); enabled = (Get-G360Prop $sp 'accountEnabled'); graph = @($graphNames | Sort-Object -Unique); pbi = $pbi; other = @($other | Sort-Object -Unique); delegated = $deleg; external = ((Get-G360Prop $sp 'appOwnerOrganizationId') -and $S.TenantId -and ((Get-G360Prop $sp 'appOwnerOrganizationId') -ne $S.TenantId)) }
    }
    $S.G360Sps = $list
    $S.EntraRead = $true
    $main = $null
    foreach ($x in $list) { if ($x.name -eq $G360AppName) { $main = $x } }
    if ($null -eq $main) { foreach ($x in $list) { if ($null -eq $main -or @($x.graph).Count -gt @($main.graph).Count) { $main = $x } } }
    $S.MainSp = $main
    if ($null -ne $main) { $S.GrantedGraph = @($main.graph) }
    foreach ($x in $list) { $S.PbiPermsOnG360 += $x.pbi }

    if (@($list).Count -eq 0 -and @($apps).Count -eq 0) {
        Add-G360Result 'entra' 'Govern360 app registration' 'missing' ('No app registration or enterprise app named "Govern360" exists yet. This is normal before onboarding: the Govern360 Microsoft connection script creates "' + $G360AppName + '".') 'Application Administrator (create) + Global Administrator (consent)'
        Add-G360Action 'entra' ('Run the Govern360 Microsoft connection setup to create the "' + $G360AppName + '" app, then grant admin consent for ' + @($DefaultScopes).Count + ' Microsoft Graph application permissions') 'Global Administrator' 1
    } else {
        $names = @($list | ForEach-Object { $_.name + ' (' + @($_.graph).Count + ' Graph application permissions)' })
        Add-G360Result 'entra' 'Govern360 app registration' 'ok' ('Found: ' + ($names -join '; ') + '.') ''
    }
}
Invoke-G360Check 'entra' 'Required Graph permissions' {
    if (-not $S.EntraRead) { Add-G360Result 'entra' 'Required Graph permissions' 'not_checked' 'App registrations could not be read (needs Application.Read.All or Global Reader).' 'Global Reader'; return }
    $permRows = @()
    $missingDefault = @()
    foreach ($m in $MsModules) {
        foreach ($scp in $m.scopes) {
            $st = 'Not granted'
            if ($null -eq $S.MainSp) { $st = 'App not created yet' }
            elseif (@($S.GrantedGraph) -contains $scp) { $st = 'Granted' }
            elseif (-not $m.defaultOn) { $st = 'Not requested (optional)' }
            if ($m.defaultOn -and @($S.GrantedGraph) -notcontains $scp -and $missingDefault -notcontains $scp) { $missingDefault += $scp }
            $on = 'Off'
            if ($m.defaultOn) { $on = 'On' }
            $permRows += , @($m.label, $on, $scp, $ScopeHelp[$scp], $st)
        }
    }
    Add-G360Table 'entra' 'Microsoft Graph application permissions Govern360 requests (per module)' @('Govern360 module', 'On by default', 'Permission (Application, read-only)', 'What it reads', 'Status') $permRows 'Govern360 resolves each permission by name from the Microsoft Graph service principal in your own tenant, and grants them in one admin-consent pass.'
    if ($null -eq $S.MainSp) {
        Add-G360Result 'entra' 'Required Graph permissions' 'missing' ('None granted yet: ' + @($DefaultScopes).Count + ' default permissions are needed (' + ($DefaultScopes -join ', ') + ').') 'Global Administrator or Privileged Role Administrator'
    } elseif (@($missingDefault).Count -eq 0) {
        Add-G360Result 'entra' 'Required Graph permissions' 'ok' ('All ' + @($DefaultScopes).Count + ' default Microsoft Graph application permissions are granted to ' + $S.MainSp.name + '.') ''
    } else {
        Add-G360Result 'entra' 'Required Graph permissions' 'missing' (@($missingDefault).Count.ToString() + ' of ' + @($DefaultScopes).Count + ' default permissions are not granted to ' + $S.MainSp.name + ': ' + ($missingDefault -join ', ') + '.') 'Global Administrator or Privileged Role Administrator'
        Add-G360Action 'entra' ('Grant admin consent for ' + @($missingDefault).Count + ' Microsoft Graph permissions on "' + $S.MainSp.name + '": ' + ($missingDefault -join ', ')) 'Global Administrator' 1
    }
    $optOn = @()
    foreach ($m in $MsModules) { if (-not $m.defaultOn) { $all = $true; foreach ($scp in $m.scopes) { if (@($S.GrantedGraph) -notcontains $scp) { $all = $false } }; if ($all -and $null -ne $S.MainSp) { $optOn += $m.label } } }
    if (@($optOn).Count -gt 0) { Add-G360Result 'entra' 'Optional modules granted' 'ok' ($optOn -join ', ') '' }
    else { Add-G360Result 'entra' 'Optional modules granted' 'ok' 'None. Optional modules (AI signup email discovery, Agent Registry, Agent run activity, Copilot prompts and answers, Global Secure Access) are off by default and can be added later.' '' }
    if ($S.PbiPermsOnG360 -gt 0) {
        Add-G360Result 'entra' 'Power BI / Fabric application permissions' 'warning' ('A Govern360 app holds ' + $S.PbiPermsOnG360 + ' admin-consented Power BI / Fabric application permission(s). Microsoft blocks read-only Fabric admin APIs for a service principal that has them.') 'Application Administrator'
        Add-G360Action 'fabric' 'Remove admin-consented Power BI Service application permissions from the Govern360 app (Fabric read-only admin APIs refuse apps that hold them)' 'Application Administrator' 2
    }
}
Invoke-G360Check 'entra' 'Credential expiry' {
    if (-not $S.EntraRead) { return }
    $rows = @(); $expired = 0; $soon = 0
    $now = (Get-Date).ToUniversalTime()
    foreach ($a in $G360Apps) {
        $creds = @()
        foreach ($c in @(Get-G360Prop $a 'passwordCredentials')) { if ($null -ne $c) { $creds += , @('Secret', $c) } }
        foreach ($c in @(Get-G360Prop $a 'keyCredentials')) { if ($null -ne $c) { $creds += , @('Certificate', $c) } }
        foreach ($pair in $creds) {
            $c = $pair[1]
            $end = ConvertTo-G360Date (Get-G360Prop $c 'endDateTime')
            $st = 'Valid'
            if ($null -ne $end -and $end -lt $now) { $st = 'Expired'; $expired++ }
            elseif ($null -ne $end -and $end -lt $now.AddDays(30)) { $st = 'Expires within 30 days'; $soon++ }
            $nm = Get-G360Prop $c 'displayName'
            if (-not $nm) { $nm = '(no name)' }
            $ed = '-'
            if ($null -ne $end) { $ed = $end.ToString('yyyy-MM-dd') }
            $rows += , @((Get-G360Prop $a 'displayName'), $nm, $pair[0], $ed, $st)
        }
    }
    if (@($rows).Count -gt 0) { Add-G360Table 'entra' 'Govern360 app credentials (names and dates only - values are never read)' @('App', 'Credential name', 'Type', 'Expires (UTC)', 'Status') $rows '' }
    if (@($G360Apps).Count -eq 0) { Add-G360Result 'entra' 'Credential expiry' 'ok' 'No Govern360 app registration in this tenant, so no credentials to check.' ''; return }
    if (@($rows).Count -eq 0) { Add-G360Result 'entra' 'Credential expiry' 'warning' 'The Govern360 app has no secret or certificate; Govern360 cannot sign in as it until one is added.' 'Application Administrator'; return }
    if ($expired -gt 0) {
        Add-G360Result 'entra' 'Credential expiry' 'missing' ($expired.ToString() + ' credential(s) expired, ' + $soon + ' expire within 30 days.') 'Application Administrator'
        Add-G360Action 'entra' 'Add a new client secret to the Govern360 app (keep the others: az ad app credential reset --append) and update it in Govern360 Connections' 'Application Administrator' 1
    } elseif ($soon -gt 0) {
        Add-G360Result 'entra' 'Credential expiry' 'warning' ($soon.ToString() + ' credential(s) expire within 30 days.') 'Application Administrator'
        Add-G360Action 'entra' 'Add a new client secret to the Govern360 app before the current one expires (append, do not replace)' 'Application Administrator' 2
    } else { Add-G360Result 'entra' 'Credential expiry' 'ok' (@($rows).Count.ToString() + ' credential(s), none expiring within 30 days.') '' }
}
if (-not $S.EntraRead) { Set-G360Module 'entra' 'Not available' 'App registrations could not be read.' }
elseif ($null -eq $S.MainSp) { Set-G360Module 'entra' 'Needs action' ('Govern360 app not created yet; ' + @($DefaultScopes).Count + ' Graph permissions to consent.') }
else {
    $miss = @($DefaultScopes | Where-Object { @($S.GrantedGraph) -notcontains $_ })
    $bad = @($Results | Where-Object { $_.module -eq 'entra' -and ($_.status -eq 'missing' -or $_.status -eq 'warning') })
    if (@($miss).Count -eq 0 -and @($bad).Count -eq 0) { Set-G360Module 'entra' 'Ready' ('All ' + @($DefaultScopes).Count + ' default Graph permissions granted.') }
    else { Set-G360Module 'entra' 'Needs action' (@($miss).Count.ToString() + ' of ' + @($DefaultScopes).Count + ' default Graph permissions missing.') }
}

# ===========================================================================
# 3. Licences (counts only)
# ===========================================================================
Write-G360Step 3 'Licences'
$LicCats = @(
    @{ key = 'copilot'; label = 'Microsoft 365 Copilot'; sku = '(?i)copilot'; skuNot = '(?i)studio|github|pro'; plan = '^M365_COPILOT'; need = 'Microsoft 365 Copilot seats and usage report; Copilot prompts and answers' },
    @{ key = 'e5'; label = 'Microsoft 365 / Office 365 E5'; sku = '(?i)^(SPE_E5|ENTERPRISEPREMIUM|ENTERPRISEPREMIUM_NOPSTNCONF|SPE_E5_NOPSTNCONF|M365_E5|Microsoft_365_E5)'; skuNot = ''; plan = ''; need = 'Purview / DLP alerts, audit, Defender signals' },
    @{ key = 'e3'; label = 'Microsoft 365 / Office 365 E3'; sku = '(?i)^(SPE_E3|ENTERPRISEPACK|M365_E3|Microsoft_365_E3|SPE_E3_USGOV)'; skuNot = ''; plan = ''; need = 'Baseline Microsoft 365' },
    @{ key = 'bp'; label = 'Microsoft 365 Business Premium'; sku = '(?i)^(SPB|O365_BUSINESS_PREMIUM|Microsoft_365_Business_Premium)'; skuNot = ''; plan = ''; need = 'Baseline Microsoft 365 with Entra ID P1 and Intune' },
    @{ key = 'p1'; label = 'Entra ID P1'; sku = ''; skuNot = ''; plan = '^AAD_PREMIUM$'; need = 'Conditional Access' },
    @{ key = 'p2'; label = 'Entra ID P2'; sku = ''; skuNot = ''; plan = '^AAD_PREMIUM_P2$'; need = 'PIM, Conditional Access based on sign-in risk' },
    @{ key = 'intune'; label = 'Intune'; sku = ''; skuNot = ''; plan = '^INTUNE_A'; need = 'Device posture' },
    @{ key = 'purview'; label = 'Purview / compliance (E5 Compliance, MIP P2, advanced audit, endpoint DLP)'; sku = '(?i)INFORMATION_PROTECTION_COMPLIANCE|M365_E5_COMPLIANCE|PURVIEW'; skuNot = ''; plan = '^(MIP_S_CLP2|M365_ADVANCED_AUDITING|MICROSOFTENDPOINTDLP|INSIDER_RISK)'; need = 'Purview / DLP alerts, sensitivity labels, DLP events' },
    @{ key = 'studio'; label = 'Copilot Studio / Power Virtual Agents'; sku = '(?i)COPILOT_STUDIO|VIRTUAL_AGENT|CCIBOTS|POWER_VIRTUAL'; skuNot = ''; plan = '(?i)^(COPILOT_STUDIO|VIRTUAL_AGENT|CCIBOTS)'; need = 'Power Platform agent inventory and Copilot Credits' },
    @{ key = 'pp'; label = 'Power Apps / Power Automate / Dataverse capacity'; sku = '(?i)^(POWERAPPS_PER|POWER_APPS_PER|FLOW_PER|POWERAUTOMATE|CDS_|DATAVERSE|POWERAPPS_DEV|FLOW_FREE|POWERAPPS_VIRAL)'; skuNot = ''; plan = ''; need = 'Power Platform environments' },
    @{ key = 'fabric'; label = 'Power BI / Fabric'; sku = '(?i)POWER_BI|PBI_PREMIUM|FABRIC'; skuNot = ''; plan = '^(BI_AZURE_P|PBI_PREMIUM)'; need = 'Microsoft Fabric' },
    @{ key = 'agent365'; label = 'Agent 365'; sku = '(?i)AGENT.?365'; skuNot = ''; plan = '(?i)AGENT.?365'; need = 'Agent Registry (Agent 365) - optional module' }
)
Invoke-G360Check 'licences' 'Subscribed licences' {
    $skus = @(Get-G360GraphItems 'v1.0/subscribedSkus?$select=skuPartNumber,prepaidUnits,consumedUnits,servicePlans,capabilityStatus')
    foreach ($c in $LicCats) { $S.Lic[$c.key] = @{ enabled = 0; consumed = 0; skus = @() } }
    $rows = @()
    foreach ($k in $skus) {
        $part = [string](Get-G360Prop $k 'skuPartNumber')
        $en = [int](Get-G360Prop (Get-G360Prop $k 'prepaidUnits') 'enabled')
        $co = [int](Get-G360Prop $k 'consumedUnits')
        $plans = @(@(Get-G360Prop $k 'servicePlans') | ForEach-Object { [string](Get-G360Prop $_ 'servicePlanName') })
        $tags = @()
        foreach ($c in $LicCats) {
            $hit = $false
            if ($c.sku -and $part -match $c.sku -and (-not $c.skuNot -or $part -notmatch $c.skuNot)) { $hit = $true }
            if (-not $hit -and $c.plan) { foreach ($pl in $plans) { if ($pl -match $c.plan) { $hit = $true } } }
            if ($hit) { $S.Lic[$c.key].enabled += $en; $S.Lic[$c.key].consumed += $co; $S.Lic[$c.key].skus += $part; $tags += $c.label }
        }
        $rows += , @($part, (Format-G360Number $en), (Format-G360Number $co), [string](Get-G360Prop $k 'capabilityStatus'), (($tags | Select-Object -First 4) -join '; '))
    }
    $S.LicRead = $true
    Add-G360Table 'licences' 'All subscribed SKUs (counts only)' @('SKU part number', 'Prepaid (enabled)', 'Assigned', 'State', 'Counts toward') $rows 'A SKU counts toward a category when its name matches or when it contains the service plan (for example E5 contains Entra ID P2).'
    $sumRows = @()
    foreach ($c in $LicCats) {
        $l = $S.Lic[$c.key]
        $sumRows += , @($c.label, (Format-G360Number $l.enabled), (Format-G360Number $l.consumed), $c.need)
    }
    Add-G360Table 'licences' 'Licences by Govern360 need' @('Licence', 'Prepaid', 'Assigned', 'Used by Govern360 for') $sumRows ''
    Add-G360Result 'licences' 'Subscribed licences' 'ok' (@($skus).Count.ToString() + ' SKUs read.') ''
    foreach ($c in $LicCats) {
        $l = $S.Lic[$c.key]
        if ($c.key -eq 'e3' -or $c.key -eq 'bp' -or $c.key -eq 'agent365' -or $c.key -eq 'pp') { continue }
        if ($l.enabled -gt 0) { Add-G360Result 'licences' $c.label 'ok' ((Format-G360Number $l.consumed) + ' of ' + (Format-G360Number $l.enabled) + ' assigned.') '' }
        else { Add-G360Result 'licences' $c.label 'warning' ('None found. Affects: ' + $c.need + '.') 'Billing Administrator' }
    }
    $sum = 'Copilot ' + (Format-G360Number $S.Lic['copilot'].consumed) + '/' + (Format-G360Number $S.Lic['copilot'].enabled) + ', E5 ' + (Format-G360Number $S.Lic['e5'].enabled) + ', Entra P1 ' + (Format-G360Number $S.Lic['p1'].enabled) + ', Intune ' + (Format-G360Number $S.Lic['intune'].enabled) + '.'
    Set-G360Module 'licences' 'Ready' ('Licences read. ' + $sum)
}
if (-not $S.LicRead) {
    Set-G360Module 'licences' 'Not available' 'Licences could not be read.'
}

# ===========================================================================
# 4. Microsoft 365 Copilot seats and usage report (counts only)
# ===========================================================================
Write-G360Step 4 'Microsoft 365 Copilot seats and usage report'
$CopilotReportRead = $false; $Concealed = $null
Invoke-G360Check 'copilot' 'Copilot licences' {
    if (-not $S.LicRead) { Add-G360Result 'copilot' 'Copilot licences' 'not_checked' 'Licences were not readable.' ''; return }
    $l = $S.Lic['copilot']
    if ($l.enabled -gt 0) { Add-G360Result 'copilot' 'Copilot licences' 'ok' ((Format-G360Number $l.consumed) + ' of ' + (Format-G360Number $l.enabled) + ' Microsoft 365 Copilot licences assigned.') '' }
    else { Add-G360Result 'copilot' 'Copilot licences' 'missing' 'No Microsoft 365 Copilot licences. Seats, usage and Copilot prompts have nothing to read; Copilot Chat (free) and Copilot Studio agents are covered elsewhere.' 'Billing Administrator' }
}
Invoke-G360Check 'copilot' 'Report name concealment' {
    try {
        $rs = Get-G360Graph 'v1.0/admin/reportSettings'
        $script:Concealed = [bool](Get-G360Prop $rs 'displayConcealedNames')
        if ($script:Concealed) {
            Add-G360Result 'copilot' 'Report name concealment' 'warning' 'On. Microsoft 365 usage reports replace user names with hashed IDs, so Govern360 cannot match Copilot usage to people. Turn off "Display concealed user, group, and site names in all reports" (Microsoft 365 admin center > Settings > Org settings > Reports) if you want per-person usage.' 'Global Administrator'
            Add-G360Action 'copilot' 'Decide on report name concealment: turn off "Display concealed user, group, and site names in all reports" to see Copilot usage per person (Microsoft 365 admin center > Settings > Org settings > Reports)' 'Global Administrator' 2
        } else { Add-G360Result 'copilot' 'Report name concealment' 'ok' 'Off. Usage reports show real names, so usage can be matched to people.' '' }
    } catch { Add-G360Result 'copilot' 'Report name concealment' 'not_checked' (Get-G360DenyText $_ 'ReportSettings.Read.All and Reports Reader or Global Reader') '' }
}
Invoke-G360Check 'copilot' 'Copilot usage report (last 7 days)' {
    $done = $false; $lastErr = $null
    foreach ($path in @("v1.0/copilot/reports/getMicrosoft365CopilotUserCountSummary(period='D7')?`$format=application/json", "beta/reports/getMicrosoft365CopilotUserCountSummary(period='D7')?`$format=application/json")) {
        if ($done) { break }
        try {
            $r = Get-G360Graph $path
            $v = @(Get-G360Prop $r 'value')[0]
            $ad = @(Get-G360Prop $v 'adoptionByProduct')
            $en = $null; $ac = $null
            if (@($ad).Count -gt 0) { $en = Get-G360Prop $ad[0] 'anyAppEnabledUsers'; $ac = Get-G360Prop $ad[0] 'anyAppActiveUsers' }
            $script:CopilotReportRead = $true; $done = $true
            Add-G360Result 'copilot' 'Copilot usage report (last 7 days)' 'ok' ('Readable. Enabled users: ' + (Format-G360Number $en) + ', active users: ' + (Format-G360Number $ac) + ' (counts only).') ''
        } catch { $lastErr = $_ }
    }
    if (-not $done) {
        try {
            $rows = @(Get-G360GraphItems "v1.0/copilot/reports/getMicrosoft365CopilotUsageUserDetail(period='D7')?`$format=application/json" -MaxPages 50)
            $active = @($rows | Where-Object { Get-G360Prop $_ 'lastActivityDate' }).Count
            $total = @($rows).Count
            $rows = $null
            $script:CopilotReportRead = $true; $done = $true
            Add-G360Result 'copilot' 'Copilot usage report (last 7 days)' 'ok' ('Readable. ' + $total + ' licensed users in the report, ' + $active + ' with Copilot activity (counts only; no names kept).') ''
        } catch { $lastErr = $_ }
    }
    if (-not $done) {
        Add-G360Result 'copilot' 'Copilot usage report (last 7 days)' 'not_checked' ((Get-G360DenyText $lastErr 'Reports Reader, Global Reader or Global Administrator') + ' Govern360 itself reads this report with the Reports.Read.All application permission, not your account.') 'Reports Reader'
    }
}
if ($S.LicRead -and $S.Lic['copilot'].enabled -eq 0) { Set-G360Module 'copilot' 'Not available' 'No Microsoft 365 Copilot licences in this tenant.' }
elseif (-not $CopilotReportRead -or $Concealed -eq $true) { Set-G360Module 'copilot' 'Needs action' 'Usage report unreadable or names concealed.' }
else { Set-G360Module 'copilot' 'Ready' 'Copilot usage report readable with names.' }
if ($S.EntraRead -and ($null -eq $S.MainSp -or @($S.GrantedGraph) -notcontains 'Reports.Read.All')) {
    Add-G360Result 'copilot' 'Govern360 permission for this report' 'missing' 'The Govern360 app does not hold Reports.Read.All yet (Microsoft 365 Trust module).' 'Global Administrator'
}

# ===========================================================================
# 5. Power Platform / Dataverse / Copilot Studio
# ===========================================================================
Write-G360Step 5 'Power Platform and Copilot Studio'
$BapBase = 'https://api.bap.microsoft.com'
$BapResource = 'https://service.powerapps.com/'
$PpEnvs = @(); $PpEnvRead = $false; $PpRegistered = $null
Invoke-G360Check 'powerplatform' 'Power Platform Administrator role' {
    if (-not $S.RolesRead) { Add-G360Result 'powerplatform' 'Power Platform Administrator role' 'not_checked' 'Roles could not be read.' ''; return }
    if ((Test-G360Role 'PPAdmin') -or (Test-G360Role 'GA')) { Add-G360Result 'powerplatform' 'Power Platform Administrator role' 'ok' 'This admin holds Power Platform Administrator or Global Administrator.' '' }
    elseif (Test-G360Role 'PPAdmin' -Eligible) { Add-G360Result 'powerplatform' 'Power Platform Administrator role' 'warning' 'Eligible in PIM, not active. Activate it before the Power Platform steps.' 'Privileged Role Administrator' }
    else { Add-G360Result 'powerplatform' 'Power Platform Administrator role' 'warning' 'Not held. A Power Platform Administrator consents the Govern360 Power Platform connection and adds the Govern360 application user.' 'Privileged Role Administrator' }
}
Invoke-G360Check 'powerplatform' 'Environments' {
    try {
        $envs = @(Get-G360RestItems -Resource $BapResource -Uri ($BapBase + '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01&$expand=properties'))
    } catch {
        Add-G360Result 'powerplatform' 'Environments' 'not_checked' (Get-G360DenyText $_ 'Power Platform Administrator') 'Power Platform Administrator'
        return
    }
    $list = @()
    foreach ($e in $envs) {
        $p = Get-G360Prop $e 'properties'
        $meta = Get-G360Prop $p 'linkedEnvironmentMetadata'
        $url = [string](Get-G360Prop $meta 'instanceApiUrl')
        if (-not $url) { $url = [string](Get-G360Prop $meta 'instanceUrl') }
        $type = [string](Get-G360Prop $p 'environmentSku')
        if ((Get-G360Prop $p 'isDefault') -eq $true) { $type = 'Default' }
        $gov = Get-G360Prop $p 'governanceConfiguration'
        $managed = ([string](Get-G360Prop $gov 'protectionLevel')) -eq 'Standard'
        $list += , @{ id = (Get-G360Prop $e 'name'); name = [string](Get-G360Prop $p 'displayName'); type = $type; region = [string](Get-G360Prop $e 'location'); url = $url.TrimEnd('/'); dataverse = [bool]$url; managed = $managed; agents = '-' }
    }
    $script:PpEnvs = $list; $script:PpEnvRead = $true
    $dv = @($list | Where-Object { $_.dataverse }).Count
    $mg = @($list | Where-Object { $_.managed }).Count
    $byType = @($list | Group-Object { $_.type } | ForEach-Object { $_.Name + ' ' + $_.Count }) -join ', '
    Add-G360Result 'powerplatform' 'Environments' 'ok' (@($list).Count.ToString() + ' environments (' + $byType + '); ' + $dv + ' with Dataverse; ' + $mg + ' managed.') ''
}
Invoke-G360Check 'powerplatform' 'Copilot Studio agents (sample)' {
    if ($SkipDataverse) { Add-G360Result 'powerplatform' 'Copilot Studio agents (sample)' 'not_checked' 'Skipped (-SkipDataverse).' ''; return }
    if (-not $PpEnvRead) { Add-G360Result 'powerplatform' 'Copilot Studio agents (sample)' 'not_checked' 'Environments were not listed.' ''; return }
    $dvEnvs = @($PpEnvs | Where-Object { $_.dataverse } | Select-Object -First $MaxDataverseEnvironments)
    if (@($dvEnvs).Count -eq 0) { Add-G360Result 'powerplatform' 'Copilot Studio agents (sample)' 'ok' 'No environment has Dataverse, so there are no Copilot Studio agents to count.' ''; return }
    $okN = 0; $deniedN = 0; $agents = 0
    foreach ($e in $dvEnvs) {
        try {
            $r = Invoke-G360Rest -Resource ($e.url + '/') -Uri ($e.url + '/api/data/v9.2/bots?$select=botid&$count=true')
            $c = Get-G360Prop $r '@odata.count'
            if ($null -eq $c) { $c = @(Get-G360Prop $r 'value').Count }
            $e.agents = [string]$c; $agents += [int]$c; $okN++
        } catch { $e.agents = 'not permitted'; $deniedN++ }
    }
    $st = 'ok'
    if ($okN -eq 0) { $st = 'not_checked' }
    Add-G360Result 'powerplatform' 'Copilot Studio agents (sample)' $st ('Counted in ' + $okN + ' of ' + @($dvEnvs).Count + ' Dataverse environments: ' + $agents + ' agents. ' + $deniedN + ' environment(s) did not allow your account to read agents (normal without a Dataverse role there; Govern360 uses its own application user).') ''
}
Invoke-G360Check 'powerplatform' 'Govern360 management application' {
    if (-not $S.EntraRead) { Add-G360Result 'powerplatform' 'Govern360 management application' 'not_checked' 'The Govern360 app could not be looked up (Microsoft Graph not available).' ''; return }
    if (@($S.G360Sps).Count -eq 0) { Add-G360Result 'powerplatform' 'Govern360 management application' 'missing' 'No Govern360 app exists yet to register.' 'Power Platform Administrator'; $script:PpRegistered = $false; return }
    try {
        $apps = @(Get-G360RestItems -Resource $BapResource -Uri ($BapBase + '/providers/Microsoft.BusinessAppPlatform/adminApplications?api-version=2020-10-01'))
        $ids = @($apps | ForEach-Object { [string](Get-G360Prop (Get-G360Prop $_ 'properties') 'applicationId'); [string](Get-G360Prop $_ 'applicationId') })
        $hit = @($S.G360Sps | Where-Object { $ids -contains $_.appId })
        if (@($hit).Count -gt 0) { $script:PpRegistered = $true; Add-G360Result 'powerplatform' 'Govern360 management application' 'ok' ('Registered: ' + ((@($hit) | ForEach-Object { $_.name }) -join ', ') + '.') '' }
        else { $script:PpRegistered = $false; Add-G360Result 'powerplatform' 'Govern360 management application' 'missing' 'No Govern360 app is registered as a Power Platform management application, so Govern360 can list only one configured environment.' 'Power Platform Administrator' }
    } catch { Add-G360Result 'powerplatform' 'Govern360 management application' 'not_checked' (Get-G360DenyText $_ 'Power Platform Administrator') 'Power Platform Administrator' }
}
Invoke-G360Check 'powerplatform' 'Copilot Credit capacity' {
    try {
        $r = Invoke-G360Rest -Resource 'https://api.powerplatform.com' -Uri 'https://api.powerplatform.com/licensing/tenantCapacity?api-version=2022-03-01-preview'
        $caps = @(Get-G360Prop $r 'tenantCapacities')
        $rel = @($caps | Where-Object { ([string](Get-G360Prop $_ 'capacityType')) -match '(?i)copilot|message|credit|agent' })
        if (@($rel).Count -eq 0) { Add-G360Result 'powerplatform' 'Copilot Credit capacity' 'ok' ('Tenant capacity readable; no Copilot Credit / message capacity found (' + @($caps).Count + ' other capacity types). Pay-as-you-go billing or no Copilot Studio capacity.') '' }
        else {
            $parts = @($rel | ForEach-Object { [string](Get-G360Prop $_ 'capacityType') + ': ' + (Format-G360Number (Get-G360Prop $_ 'totalCapacity')) + ' ' + [string](Get-G360Prop $_ 'capacityUnits') + ' total' })
            Add-G360Result 'powerplatform' 'Copilot Credit capacity' 'ok' ($parts -join '; ') ''
        }
    } catch { Add-G360Result 'powerplatform' 'Copilot Credit capacity' 'not_checked' ((Get-G360DenyText $_ 'Power Platform Administrator') + ' Best-effort check; Govern360 reads capacity through its own delegated Power Platform connection.') '' }
}
if ($PpEnvRead) {
    $envRows = @()
    foreach ($e in $PpEnvs) {
        $d = 'No'; if ($e.dataverse) { $d = 'Yes' }
        $mgd = 'No'; if ($e.managed) { $mgd = 'Yes' }
        $envRows += , @($e.name, $e.type, $e.region, $d, $mgd, $e.agents)
    }
    Add-G360Table 'powerplatform' 'Power Platform environments (names only)' @('Environment', 'Type', 'Region', 'Dataverse', 'Managed', 'Copilot Studio agents') $envRows ('Agents are counted in at most ' + $MaxDataverseEnvironments + ' Dataverse environments, with your own account.')
}
Add-G360Table 'powerplatform' 'What Govern360 needs for Power Platform' @('Step', 'Who', 'Detail') @(
    , @('Consent the Govern360 Power Platform connection', 'Power Platform Administrator', 'Delegated ResourceQuery.Resources.Read on the Power Platform API (agent inventory). Signs in once from Govern360 Connections.')
    , @('Register the Govern360 app as a management application', 'Power Platform Administrator', 'pac admin application register --application-id <Govern360 app id>. Lets Govern360 list every environment.')
    , @('Add the Govern360 application user in each environment', 'Power Platform Administrator', 'Security role "Govern360 AI Event Reader": Read (Organization) on AI Event, AI Model and User. Never System Administrator.')
) ''
if ($PpEnvRead) {
    Add-G360Action 'powerplatform' 'Connect Power Platform in Govern360: consent the Power Platform connection, register the Govern360 app (pac admin application register), and add it as an application user with the read-only "Govern360 AI Event Reader" role in each Dataverse environment' 'Power Platform Administrator' 2
    if ($PpRegistered -eq $true) { Set-G360Module 'powerplatform' 'Ready' (@($PpEnvs).Count.ToString() + ' environments; Govern360 app registered.') }
    else { Set-G360Module 'powerplatform' 'Needs action' (@($PpEnvs).Count.ToString() + ' environments listed; Govern360 connection not set up yet.') }
} else {
    Set-G360Module 'powerplatform' 'Not available' 'Environments could not be listed with this account.'
    Add-G360Action 'powerplatform' 'Have a Power Platform Administrator run this check (or connect Power Platform in Govern360) so environments can be listed' 'Power Platform Administrator' 2
}

# ===========================================================================
# 6. Azure
# ===========================================================================
Write-G360Step 6 'Azure (subscriptions, AI resources, Cost Management)'
$Arm = 'https://management.azure.com'
$AzSubRows = @(); $AzSubsSeen = 0; $G360AzNeeds = @()
Invoke-G360Check 'azure' 'Subscriptions' {
    if (-not $S.AzReady) { Add-G360Result 'azure' 'Subscriptions' 'not_checked' 'No Azure session (Az.Accounts missing or sign-in failed).' ''; return }
    $gp = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($S.TenantId) { $gp['TenantId'] = $S.TenantId }
    $subs = @(Get-AzSubscription @gp | Where-Object { ([string](Get-G360Prop $_ 'State')) -eq 'Enabled' })
    $script:AzSubsSeen = @($subs).Count
    if (@($subs).Count -eq 0) { Add-G360Result 'azure' 'Subscriptions' 'warning' 'No enabled Azure subscriptions are visible to this account.' 'Owner'; return }
    $note = ''
    if (@($subs).Count -gt $MaxSubscriptions) { $note = ' Only the first ' + $MaxSubscriptions + ' are inspected (-MaxSubscriptions).' }
    Add-G360Result 'azure' 'Subscriptions' 'ok' (@($subs).Count.ToString() + ' enabled subscriptions visible.' + $note) ''
    $types = @(
        @{ k = 'fabric'; t = 'Microsoft.Fabric/capacities' },
        @{ k = 'cog'; t = 'Microsoft.CognitiveServices/accounts' },
        @{ k = 'ml'; t = 'Microsoft.MachineLearningServices/workspaces' },
        @{ k = 'law'; t = 'Microsoft.OperationalInsights/workspaces' }
    )
    $costOk = 0; $costDenied = 0
    foreach ($sub in @($subs | Select-Object -First $MaxSubscriptions)) {
        $sid = [string](Get-G360Prop $sub 'Id'); $sname = [string](Get-G360Prop $sub 'Name')
        $scope = '/subscriptions/' + $sid
        # Your roles here (at subscription, management group or root scope; includes group-based).
        $myRoles = @(); $rolesNote = ''
        try {
            if ($S.MeId -and (Get-Command Get-AzRoleAssignment -ErrorAction SilentlyContinue)) {
                $ra = @(Get-AzRoleAssignment -ObjectId $S.MeId -ExpandPrincipalGroups -Scope $scope -ErrorAction Stop -WarningAction SilentlyContinue)
                foreach ($x in $ra) {
                    $xs = [string](Get-G360Prop $x 'Scope')
                    if ($xs -eq $scope -or $xs -eq '/' -or $xs -like '/providers/Microsoft.Management/managementGroups/*') { $myRoles += [string](Get-G360Prop $x 'RoleDefinitionName') }
                }
            } elseif ($S.MeId) {
                $ra = @(Get-G360RestItems -Resource ($Arm + '/') -Uri ($Arm + $scope + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=assignedTo('" + $S.MeId + "')"))
                foreach ($x in $ra) {
                    $rdid = ([string](Get-G360Prop (Get-G360Prop $x 'properties') 'roleDefinitionId')).Split('/')[-1]
                    $nm = $AzRoleNames[$rdid]; if (-not $nm) { $nm = 'Custom or other role' }
                    $myRoles += $nm
                }
            } else { $rolesNote = 'not read' }
        } catch { $rolesNote = 'not read' }
        $myRoles = @($myRoles | Sort-Object -Unique)
        $canAssign = @($myRoles | Where-Object { $_ -eq 'Owner' -or $_ -eq 'User Access Administrator' -or $_ -eq 'Role Based Access Control Administrator' }).Count -gt 0
        # Resources of interest (counts).
        $cnt = @{ fabric = '-'; cog = '-'; ml = '-'; law = '-' }; $openai = 0
        foreach ($ty in $types) {
            try {
                $res = @(Get-G360RestItems -Resource ($Arm + '/') -Uri ($Arm + $scope + "/resources?api-version=2021-04-01&`$filter=resourceType eq '" + $ty.t + "'"))
                if ($ty.k -eq 'cog') {
                    $openai = @($res | Where-Object { ([string](Get-G360Prop $_ 'kind')) -match '^(OpenAI|AIServices)$' }).Count
                    $cnt[$ty.k] = [string]$openai + ' (of ' + @($res).Count + ' Cognitive Services)'
                } else { $cnt[$ty.k] = [string]@($res).Count }
                if ($ty.k -eq 'fabric') { $S.FabricArmCount += @($res).Count; foreach ($f in $res) { $S.FabricArmNames += ([string](Get-G360Prop $f 'name') + ' (' + $sname + ')') } }
            } catch { $cnt[$ty.k] = 'denied' }
        }
        # Cost Management: READ-ONLY QUERY (POST is how Microsoft exposes this read). Totals only.
        $cost = 'not read'
        try {
            $to = (Get-Date).ToUniversalTime().Date
            $body = @{ type = 'Usage'; timeframe = 'Custom'; timePeriod = @{ from = $to.AddDays(-7).ToString('yyyy-MM-ddT00:00:00Z'); to = $to.AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ssZ') }; dataset = @{ granularity = 'None'; aggregation = @{ totalCost = @{ name = 'PreTaxCost'; function = 'Sum' } } } }
            $q = Invoke-G360Rest -Resource ($Arm + '/') -Uri ($Arm + $scope + '/providers/Microsoft.CostManagement/query?api-version=2025-03-01') -Method POST -Body $body -ReadOnlyQuery
            $rowsC = @(Get-G360Prop (Get-G360Prop $q 'properties') 'rows')
            $tot = 0; $cur = ''
            foreach ($rw in $rowsC) { $tot += [double]$rw[0]; if (@($rw).Count -gt 1) { $cur = [string]$rw[-1] } }
            $cost = 'Yes - ' + $tot.ToString('#,0.00', [Globalization.CultureInfo]::InvariantCulture) + ' ' + $cur + ' (7 days)'
            $costOk++
        } catch {
            $code = Get-G360HttpStatus $_
            if ($code -eq 401 -or $code -eq 403) { $cost = 'No - needs Cost Management Reader'; $costDenied++ } else { $cost = 'Error (' + $code + ')' }
        }
        # Govern360 Azure connection roles on this subscription.
        $g360Roles = @()
        foreach ($sp in $S.G360Sps) {
            try {
                if (Get-Command Get-AzRoleAssignment -ErrorAction SilentlyContinue) {
                    foreach ($x in @(Get-AzRoleAssignment -ObjectId $sp.id -Scope $scope -ErrorAction Stop -WarningAction SilentlyContinue)) {
                        $xs = [string](Get-G360Prop $x 'Scope')
                        if ($xs -eq $scope -or $xs -eq '/' -or $xs -like '/providers/Microsoft.Management/managementGroups/*') { $g360Roles += [string](Get-G360Prop $x 'RoleDefinitionName') }
                    }
                }
            } catch { Write-Verbose 'Govern360 role assignments not read.' }
        }
        $g360Roles = @($g360Roles | Sort-Object -Unique)
        $hasReader = @($g360Roles | Where-Object { $_ -eq 'Reader' -or $_ -eq 'Owner' -or $_ -eq 'Contributor' }).Count -gt 0
        $hasCost = @($g360Roles | Where-Object { $_ -eq 'Cost Management Reader' -or $_ -eq 'Cost Management Contributor' -or $_ -eq 'Owner' -or $_ -eq 'Contributor' }).Count -gt 0
        if (-not ($hasReader -and $hasCost)) { $script:G360AzNeeds += , @{ name = $sname; reader = $hasReader; cost = $hasCost } }
        $mine = ($myRoles -join ', '); if (-not $mine) { if ($rolesNote) { $mine = $rolesNote } else { $mine = 'none at subscription level' } }
        $ca = 'No'; if ($canAssign) { $ca = 'Yes' }
        $g3 = ($g360Roles -join ', '); if (-not $g3) { $g3 = 'none' }
        $script:AzSubRows += , @($sname, $mine, $ca, $cost, $cnt.fabric, $cnt.cog, $cnt.ml, $cnt.law, $g3)
    }
    if ($costOk -gt 0 -and $costDenied -eq 0) { Add-G360Result 'azure' 'Cost Management query (7 days)' 'ok' ('Permitted on all ' + $costOk + ' inspected subscriptions (read-only query, totals only).') '' }
    elseif ($costOk -gt 0) { Add-G360Result 'azure' 'Cost Management query (7 days)' 'warning' ('Permitted on ' + $costOk + ', refused on ' + $costDenied + ' subscription(s): this account lacks Cost Management Reader there.') 'Owner or User Access Administrator' }
    else { Add-G360Result 'azure' 'Cost Management query (7 days)' 'warning' 'Refused or not read on every inspected subscription.' 'Owner or User Access Administrator' }
    $openaiTotal = 0
    foreach ($row in $AzSubRows) { $m2 = [regex]::Match([string]$row[5], '^\d+'); if ($m2.Success) { $openaiTotal += [int]$m2.Value } }
    Add-G360Result 'azure' 'AI resources' 'ok' ('Azure OpenAI / AI Services accounts: ' + $openaiTotal + '. Fabric capacities: ' + $S.FabricArmCount + '. Across inspected subscriptions.') ''
}
if (@($AzSubRows).Count -gt 0) {
    Add-G360Table 'azure' 'Subscriptions (names and counts only)' @('Subscription', 'Your roles', 'Can assign roles', 'Cost readable', 'Fabric capacities', 'Azure OpenAI / AI Services', 'ML workspaces', 'Log Analytics', 'Govern360 connection roles') $AzSubRows 'Govern360 needs Reader and Cost Management Reader on each subscription it reads (Security Reader too for Security Posture). Owner or User Access Administrator can assign them.'
}
$azSpExists = $false
foreach ($row in $AzSubRows) { if ([string]$row[8] -ne 'none') { $azSpExists = $true } }
if (-not $S.AzReady) { Set-G360Module 'azure' 'Not available' 'Azure sign-in was not available, so Azure was not checked.' }
elseif ($AzSubsSeen -eq 0) {
    Set-G360Module 'azure' 'Not available' 'No Azure subscriptions visible to this account.'
} else {
    if (-not $azSpExists) {
        Add-G360Result 'azure' 'Govern360 Azure connection' 'missing' 'No Govern360 service principal holds a role on the inspected subscriptions. Create the Govern360 Azure connection (Govern360 onboarding wizard, Azure script).' 'Owner or User Access Administrator'
        Add-G360Action 'azure' ('Create the Govern360 Azure connection and assign Reader + Cost Management Reader on ' + @($AzSubRows).Count + ' subscription(s)') 'Owner or User Access Administrator' 2
    } else {
        foreach ($n in $G360AzNeeds) {
            $want = @(); if (-not $n.reader) { $want += 'Reader' }; if (-not $n.cost) { $want += 'Cost Management Reader' }
            Add-G360Action 'azure' ('Assign ' + ($want -join ' + ') + ' to the Govern360 Azure connection on subscription "' + $n.name + '"') 'Owner' 2
        }
        if (@($G360AzNeeds).Count -gt 0) { Add-G360Result 'azure' 'Govern360 Azure connection' 'warning' ('Missing Reader or Cost Management Reader on ' + @($G360AzNeeds).Count + ' subscription(s).') 'Owner or User Access Administrator' }
        else { Add-G360Result 'azure' 'Govern360 Azure connection' 'ok' 'Holds Reader and Cost Management Reader on every inspected subscription.' '' }
    }
    $bad = @($Results | Where-Object { $_.module -eq 'azure' -and ($_.status -eq 'missing' -or $_.status -eq 'warning') })
    if (@($bad).Count -eq 0) { Set-G360Module 'azure' 'Ready' ($AzSubsSeen.ToString() + ' subscriptions; Govern360 connection has the roles it needs.') }
    else { Set-G360Module 'azure' 'Needs action' ($AzSubsSeen.ToString() + ' subscriptions; roles to assign.') }
}

# ===========================================================================
# 7. Microsoft Fabric
# ===========================================================================
Write-G360Step 7 'Microsoft Fabric'
$FabricBase = 'https://api.fabric.microsoft.com'
$FabricCaps = @(); $FabricCapsRead = $false; $FabricSettingsState = 'unknown'
Invoke-G360Check 'fabric' 'Capacities visible' {
    try {
        $caps = @(Get-G360RestItems -Resource $FabricBase -Uri ($FabricBase + '/v1/capacities'))
        $script:FabricCaps = $caps; $script:FabricCapsRead = $true
        $rows = @()
        foreach ($c in $caps) { $rows += , @([string](Get-G360Prop $c 'displayName'), [string](Get-G360Prop $c 'sku'), [string](Get-G360Prop $c 'region'), [string](Get-G360Prop $c 'state')) }
        if (@($rows).Count -gt 0) { Add-G360Table 'fabric' 'Fabric capacities visible to you (names only)' @('Capacity', 'SKU', 'Region', 'State') $rows 'The Fabric API lists capacities where you are capacity administrator or contributor. Azure shows F SKUs billed through Azure.' }
        Add-G360Result 'fabric' 'Capacities visible' 'ok' ('Visible to you in Fabric: ' + @($caps).Count + '. Microsoft.Fabric/capacities resources in Azure: ' + $S.FabricArmCount + '.') ''
    } catch { Add-G360Result 'fabric' 'Capacities visible' 'not_checked' (Get-G360DenyText $_ 'a Fabric or Power BI licence for your account') '' }
}
Invoke-G360Check 'fabric' 'Fabric Administrator role' {
    if (-not $S.RolesRead) { Add-G360Result 'fabric' 'Fabric Administrator role' 'not_checked' 'Roles could not be read.' ''; return }
    if ((Test-G360Role 'FabricAdmin') -or (Test-G360Role 'GA')) { Add-G360Result 'fabric' 'Fabric Administrator role' 'ok' 'This admin holds Fabric Administrator or Global Administrator.' '' }
    elseif (Test-G360Role 'FabricAdmin' -Eligible) { Add-G360Result 'fabric' 'Fabric Administrator role' 'warning' 'Eligible in PIM, not active.' 'Privileged Role Administrator' }
    else { Add-G360Result 'fabric' 'Fabric Administrator role' 'warning' 'Not held. A Fabric Administrator changes the tenant settings Govern360 needs.' 'Privileged Role Administrator' }
}
Invoke-G360Check 'fabric' 'Service principal tenant settings' {
    try {
        $r = Invoke-G360Rest -Resource $FabricBase -Uri ($FabricBase + '/v1/admin/tenantsettings')
        $all = @(Get-G360Prop $r 'tenantSettings'); if (@($all).Count -eq 0) { $all = @(Get-G360Prop $r 'value') }
        $want = @(
            @{ title = 'Service principals can call Fabric public APIs'; rx = '(?i)service principals can (call|use) (fabric|power bi) (public )?apis'; names = @('ServicePrincipalAccess') },
            @{ title = 'Service principals can access read-only admin APIs'; rx = '(?i)service principals can access read-only admin apis|allow service principals to use read-only admin apis'; names = @('AllowServicePrincipalsUseReadAdminAPIs') }
        )
        $rows = @(); $offN = 0
        foreach ($w in $want) {
            $hit = $null
            foreach ($t in $all) {
                $tt = [string](Get-G360Prop $t 'title'); $sn = [string](Get-G360Prop $t 'settingName')
                if (($tt -match $w.rx) -or ($w.names -contains $sn)) { $hit = $t; break }
            }
            if ($null -eq $hit) { $rows += , @($w.title, 'Not found', '-'); $offN++; continue }
            $en = [bool](Get-G360Prop $hit 'enabled')
            $groups = @(@(Get-G360Prop $hit 'enabledSecurityGroups') | ForEach-Object { [string](Get-G360Prop $_ 'name') })
            $gtxt = 'Whole organisation'; if (@($groups).Count -gt 0) { $gtxt = 'Security groups: ' + ($groups -join ', ') }
            if (-not $en) { $gtxt = '-'; $offN++ }
            $et = 'Disabled'; if ($en) { $et = 'Enabled' }
            $rows += , @($w.title, $et, $gtxt)
        }
        Add-G360Table 'fabric' 'Fabric tenant settings for service principals' @('Setting', 'State', 'Applies to') $rows 'When a setting applies to security groups, the Govern360 app must be a member of one of them.'
        if ($offN -eq 0) { $script:FabricSettingsState = 'on'; Add-G360Result 'fabric' 'Service principal tenant settings' 'ok' 'Both settings are enabled. Make sure the Govern360 app is in the security group if they are scoped to groups.' '' }
        else { $script:FabricSettingsState = 'off'; Add-G360Result 'fabric' 'Service principal tenant settings' 'missing' ($offN.ToString() + ' of 2 settings are not enabled.') 'Fabric Administrator' }
    } catch {
        Add-G360Result 'fabric' 'Service principal tenant settings' 'not_checked' ((Get-G360DenyText $_ 'Fabric Administrator') + ' Ask a Fabric Administrator to confirm the two settings in the Fabric admin portal > Tenant settings > Developer settings / Admin API settings.') 'Fabric Administrator'
    }
}
$fabricAny = ($S.FabricArmCount -gt 0) -or (@($FabricCaps).Count -gt 0)
if (-not $fabricAny -and ($FabricCapsRead -or $AzSubsSeen -gt 0)) { Set-G360Module 'fabric' 'Not available' 'No Fabric capacities found in Fabric or Azure.' }
elseif (-not $fabricAny) { Set-G360Module 'fabric' 'Not available' 'Fabric capacities could not be read.' }
else {
    if ($FabricSettingsState -ne 'on') {
        Add-G360Action 'fabric' 'Enable the two Fabric tenant settings ("Service principals can call Fabric public APIs" and "Service principals can access read-only admin APIs") for a security group that contains the Govern360 app' 'Fabric Administrator' 2
    }
    if ($FabricSettingsState -eq 'on' -and $S.PbiPermsOnG360 -eq 0) { Set-G360Module 'fabric' 'Ready' 'Capacities found and service principal settings enabled.' }
    elseif ($FabricSettingsState -eq 'unknown') { Set-G360Module 'fabric' 'Needs action' 'Capacities found; tenant settings need a Fabric Administrator to confirm.' }
    else { Set-G360Module 'fabric' 'Needs action' 'Capacities found; tenant settings to enable.' }
}

# ===========================================================================
# 8. Purview & compliance
# ===========================================================================
Write-G360Step 8 'Purview and compliance'
$DlpCount = $null
Invoke-G360Check 'purview' 'Compliance role' {
    if (-not $S.RolesRead) { Add-G360Result 'purview' 'Compliance role' 'not_checked' 'Roles could not be read.' ''; return }
    $held = @()
    foreach ($k in @('ComplianceAdmin', 'SecAdmin', 'SecReader', 'GlobalReader', 'GA')) { if (Test-G360Role $k) { $held += (Get-G360RoleName $k) } }
    if (@($held).Count -gt 0) { Add-G360Result 'purview' 'Compliance role' 'ok' ('Holds: ' + ($held -join ', ') + '.') '' }
    else { Add-G360Result 'purview' 'Compliance role' 'warning' 'No Compliance Administrator, Security Administrator/Reader or Global Reader role; Purview settings could not be reviewed by this account.' 'Privileged Role Administrator' }
}
Invoke-G360Check 'purview' 'Purview licence' {
    if (-not $S.LicRead) { Add-G360Result 'purview' 'Purview licence' 'not_checked' 'Licences were not readable.' ''; return }
    if ($S.Lic['purview'].enabled -gt 0 -or $S.Lic['e5'].enabled -gt 0) { Add-G360Result 'purview' 'Purview licence' 'ok' 'E5 or Purview compliance licences found; DLP alerts and advanced audit are available.' '' }
    else { Add-G360Result 'purview' 'Purview licence' 'warning' 'No E5 or Purview compliance licence found. Purview and Defender alerts need a Microsoft 365 E5 or Purview licence.' 'Billing Administrator' }
}
Invoke-G360Check 'purview' 'DLP policies' {
    if (-not $IncludePurview) {
        Add-G360Result 'purview' 'DLP policies' 'not_checked' 'Not checked: Microsoft Graph has no read-only API for DLP policies. Re-run with -IncludePurview to count them through a read-only Security & Compliance PowerShell session (Get-DlpCompliancePolicy).' ''
        return
    }
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Add-G360Result 'purview' 'DLP policies' 'not_checked' 'ExchangeOnlineManagement is not installed: Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser' ''
        return
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop -WarningAction SilentlyContinue
    $cp = @{ ErrorAction = 'Stop'; ShowBanner = $false }
    if ($S.Upn) { $cp['UserPrincipalName'] = $S.Upn }
    try {
        Connect-IPPSSession @cp
        $pol = @(Get-DlpCompliancePolicy -ErrorAction Stop)
        $script:DlpCount = @($pol).Count
        $on = @($pol | Where-Object { ([string](Get-G360Prop $_ 'Mode')) -eq 'Enable' }).Count
        Add-G360Result 'purview' 'DLP policies' 'ok' (@($pol).Count.ToString() + ' DLP policies (' + $on + ' enforced). Counts only.') ''
    } catch { Add-G360Result 'purview' 'DLP policies' 'not_checked' (Get-G360DenyText $_ 'Compliance Administrator') 'Compliance Administrator' }
    finally { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { Write-Verbose 'Session already closed.' } }
}
Invoke-G360Check 'purview' 'Govern360 permission for Purview alerts' {
    if (-not $S.EntraRead) { Add-G360Result 'purview' 'Govern360 permission for Purview alerts' 'not_checked' 'The Govern360 app could not be looked up.' ''; return }
    if ($null -ne $S.MainSp -and @($S.GrantedGraph) -contains 'SecurityAlert.Read.All') { Add-G360Result 'purview' 'Govern360 permission for Purview alerts' 'ok' 'SecurityAlert.Read.All is granted to the Govern360 app.' '' }
    else { Add-G360Result 'purview' 'Govern360 permission for Purview alerts' 'missing' 'SecurityAlert.Read.All (Purview / DLP module) is not granted to a Govern360 app yet.' 'Global Administrator' }
}
if ($S.LicRead -and $S.Lic['purview'].enabled -eq 0 -and $S.Lic['e5'].enabled -eq 0) { Set-G360Module 'purview' 'Not available' 'No E5 or Purview licence: no DLP alerts to read.' }
else {
    $bad = @($Results | Where-Object { $_.module -eq 'purview' -and ($_.status -eq 'missing' -or $_.status -eq 'warning') })
    if (@($bad).Count -eq 0) { Set-G360Module 'purview' 'Ready' 'Licensed and Govern360 can read Purview alerts.' }
    else { Set-G360Module 'purview' 'Needs action' 'Licensed; Govern360 permission or role still needed.' }
}

# ===========================================================================
# 9. Intune / endpoints (counts only)
# ===========================================================================
Write-G360Step 9 'Device posture (Intune)'
$IntuneCount = $null
Invoke-G360Check 'intune' 'Managed devices' {
    if ($SkipIntune) { Add-G360Result 'intune' 'Managed devices' 'not_checked' 'Skipped (-SkipIntune).' ''; return }
    try {
        $o = Get-G360Graph 'v1.0/deviceManagement/managedDeviceOverview'
        $script:IntuneCount = [int](Get-G360Prop $o 'enrolledDeviceCount')
        $os = Get-G360Prop $o 'deviceOperatingSystemSummary'
        $rows = @()
        foreach ($pair in @(@('Windows', 'windowsCount'), @('macOS', 'macOSCount'), @('iOS / iPadOS', 'iosCount'), @('Android', 'androidCount'), @('Linux', 'linuxCount'), @('Windows Mobile', 'windowsMobileCount'))) {
            $v = Get-G360Prop $os $pair[1]
            if ($null -ne $v) { $rows += , @($pair[0], (Format-G360Number $v)) }
        }
        Add-G360Table 'intune' 'Managed devices by operating system (counts only)' @('Operating system', 'Devices') $rows ''
        Add-G360Result 'intune' 'Managed devices' 'ok' ((Format-G360Number $script:IntuneCount) + ' enrolled devices.') ''
    } catch { Add-G360Result 'intune' 'Managed devices' 'not_checked' (Get-G360DenyText $_ 'Intune Administrator, Global Reader or an Intune read role') 'Intune Administrator' }
}
$devMiss = @(@('DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All') | Where-Object { @($S.GrantedGraph) -notcontains $_ })
if (-not $S.EntraRead) { Add-G360Result 'intune' 'Govern360 permissions for device posture' 'not_checked' 'The Govern360 app could not be looked up.' '' }
elseif (@($devMiss).Count -gt 0) { Add-G360Result 'intune' 'Govern360 permissions for device posture' 'missing' ('Not granted to a Govern360 app yet: ' + ($devMiss -join ', ') + '.') 'Global Administrator' }
else { Add-G360Result 'intune' 'Govern360 permissions for device posture' 'ok' 'Both device posture permissions are granted.' '' }
if ($SkipIntune) { Set-G360Module 'intune' 'Not available' 'Skipped by request.' }
elseif ($null -ne $IntuneCount -and $IntuneCount -eq 0) { Set-G360Module 'intune' 'Not available' 'No Intune-managed devices.' }
elseif ($null -eq $IntuneCount) { Set-G360Module 'intune' 'Not available' 'Managed devices could not be read.' }
elseif (@($devMiss).Count -gt 0 -or -not $S.EntraRead) { Set-G360Module 'intune' 'Needs action' ((Format-G360Number $IntuneCount) + ' managed devices; Govern360 permissions pending.') }
else { Set-G360Module 'intune' 'Ready' ((Format-G360Number $IntuneCount) + ' managed devices.') }

# ===========================================================================
# 10. Entra identity signals (counts only)
# ===========================================================================
Write-G360Step 10 'Identity & groups and Conditional Access'
$IdRead = $false
Invoke-G360Check 'identity' 'Directory size' {
    $u = Get-G360GraphCount 'v1.0/users/$count'
    $g = Get-G360GraphCount 'v1.0/groups/$count'
    $sp = Get-G360GraphCount 'v1.0/servicePrincipals/$count'
    $script:IdRead = $true
    Add-G360Result 'identity' 'Directory size' 'ok' ((Format-G360Number $u) + ' users, ' + (Format-G360Number $g) + ' groups, ' + (Format-G360Number $sp) + ' service principals (enterprise apps and agents).') ''
}
Invoke-G360Check 'identity' 'App credentials expiring in 30 days' {
    $apps = @(Get-G360GraphItems 'v1.0/applications?$select=id,passwordCredentials,keyCredentials&$top=999' -MaxPages 30)
    $now = (Get-Date).ToUniversalTime(); $soon = 0; $exp = 0
    foreach ($a in $apps) {
        $s1 = $false; $e1 = $false
        foreach ($c in (@(Get-G360Prop $a 'passwordCredentials') + @(Get-G360Prop $a 'keyCredentials'))) {
            if ($null -eq $c) { continue }
            $end = ConvertTo-G360Date (Get-G360Prop $c 'endDateTime')
            if ($null -eq $end) { continue }
            if ($end -lt $now) { $e1 = $true } elseif ($end -lt $now.AddDays(30)) { $s1 = $true }
        }
        if ($s1) { $soon++ }
        if ($e1) { $exp++ }
    }
    $st = 'ok'; if ($soon -gt 0) { $st = 'warning' }
    Add-G360Result 'identity' 'App credentials expiring in 30 days' $st ($soon.ToString() + ' of ' + @($apps).Count + ' app registrations have a secret or certificate expiring within 30 days; ' + $exp + ' hold at least one expired credential. Govern360 tracks these as machine identities.') 'Application Administrator'
}
Invoke-G360Check 'identity' 'Conditional Access policies' {
    try {
        $pol = @(Get-G360GraphItems 'v1.0/identity/conditionalAccess/policies?$select=id,state')
        $on = @($pol | Where-Object { (Get-G360Prop $_ 'state') -eq 'enabled' }).Count
        $ro = @($pol | Where-Object { (Get-G360Prop $_ 'state') -eq 'enabledForReportingButNotEnforced' }).Count
        $off = @($pol).Count - $on - $ro
        Add-G360Result 'identity' 'Conditional Access policies' 'ok' (@($pol).Count.ToString() + ' policies: ' + $on + ' on, ' + $ro + ' report-only, ' + $off + ' off.') ''
    } catch { Add-G360Result 'identity' 'Conditional Access policies' 'not_checked' (Get-G360DenyText $_ 'Policy.Read.All with Security Reader, Global Reader or Conditional Access Administrator, and Entra ID P1') 'Security Reader' }
}
$idMiss = @(@('Directory.Read.All', 'Group.Read.All', 'Policy.Read.All', 'Application.Read.All') | Where-Object { @($S.GrantedGraph) -notcontains $_ })
if (-not $S.EntraRead) { Add-G360Result 'identity' 'Govern360 permissions for identity' 'not_checked' 'The Govern360 app could not be looked up.' '' }
elseif (@($idMiss).Count -gt 0) { Add-G360Result 'identity' 'Govern360 permissions for identity' 'missing' ('Not granted to a Govern360 app yet: ' + ($idMiss -join ', ') + '.') 'Global Administrator' }
else { Add-G360Result 'identity' 'Govern360 permissions for identity' 'ok' 'Identity & groups and Conditional Access permissions are granted.' '' }
if (-not $IdRead) { Set-G360Module 'identity' 'Not available' 'Directory could not be read.' }
elseif (@($idMiss).Count -gt 0 -or -not $S.EntraRead) { Set-G360Module 'identity' 'Needs action' 'Directory readable; Govern360 permissions pending.' }
else { Set-G360Module 'identity' 'Ready' 'Directory readable; Govern360 permissions granted.' }

# ===========================================================================
# Clean up sign-in state we created. Tokens are dropped from memory.
# ===========================================================================
$S.TokenCache.Clear()
if ($S.ConnectedGraph -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
    try { [void](Disconnect-MgGraph -ErrorAction SilentlyContinue) } catch { Write-Verbose 'Graph session already closed.' }
}

# ===========================================================================
# Report
# ===========================================================================
function ConvertTo-G360Html {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-G360StatusClass {
    param([string]$Status)
    switch ($Status) {
        'Ready' { return 'st-ready' }
        'Needs action' { return 'st-action' }
        'ok' { return 'it-ok' }
        'warning' { return 'it-warn' }
        'missing' { return 'it-miss' }
        default { return 'it-nc' }
    }
    return 'it-nc'
}

function Get-G360StatusLabel {
    param([string]$Status)
    switch ($Status) {
        'ok' { return 'OK' }
        'warning' { return 'Warning' }
        'missing' { return 'Missing' }
        'not_checked' { return 'Not checked' }
    }
    return $Status
}

$RunEnd = Get-Date
$DomainLabel = $S.Domain; if (-not $DomainLabel) { $DomainLabel = 'unknown-tenant' }
$Stamp = $RunEnd.ToString('yyyyMMdd-HHmm')
$SafeDomain = [regex]::Replace([string]$DomainLabel, '[^A-Za-z0-9\.\-]', '-')
$BaseName = 'Govern360-PrePOC-Readiness-' + $SafeDomain + '-' + $Stamp
$OutDir = $null; $HtmlPath = $null
if ($OutputPath) {
    if ($OutputPath -match '\.html?$') { $HtmlPath = $OutputPath; $OutDir = Split-Path -Parent $OutputPath; if (-not $OutDir) { $OutDir = (Get-Location).Path } }
    else { $OutDir = $OutputPath }
} elseif ($IsCloudShell -and $HOME -and (Test-Path (Join-Path $HOME 'clouddrive'))) { $OutDir = Join-Path $HOME 'clouddrive' }
else { $OutDir = (Get-Location).Path }
if (-not (Test-Path $OutDir)) { [void](New-Item -ItemType Directory -Path $OutDir -Force) }
if (-not $HtmlPath) { $HtmlPath = Join-Path $OutDir ($BaseName + '.html') }
$HtmlPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HtmlPath)
$JsonPath = [regex]::Replace($HtmlPath, '\.html?$', '') + '.json'

# A module where nothing could actually be read is never shown as Ready.
foreach ($md in $ModuleDefs) {
    $k = $md.key
    $read = @($Results | Where-Object { $_.module -eq $k -and $_.status -ne 'not_checked' })
    if (@($read).Count -eq 0) { Set-G360Module $k 'Not available' 'Could not be checked with this account - see the details below.' }
}
if ($S.GraphMode -eq 'none') { Add-G360Action 'admin' 'Re-run this check signed in to Microsoft Graph as a Global Reader or Global Administrator (Microsoft Graph sign-in failed on this run)' 'Global Reader' 1 }
elseif (-not $S.AzReady) { Add-G360Action 'admin' 'Re-run this check with an Azure sign-in (Connect-AzAccount) so Azure, Power Platform and Fabric can be checked' 'Global Reader' 2 }
$counts = @{ 'Ready' = 0; 'Needs action' = 0; 'Not available' = 0 }
foreach ($md in $ModuleDefs) { if (-not $ModuleState.ContainsKey($md.key)) { Set-G360Module $md.key 'Not available' 'Not checked.' }; $counts[$ModuleState[$md.key].status]++ }
$SortedActions = @($Actions | Sort-Object priority, @{ Expression = { $m = $_.module; ($ModuleDefs | Where-Object { $_.key -eq $m } | Select-Object -First 1).n } })
$runBy = $S.Upn; if (-not $runBy) { $runBy = 'unknown' }
$tz = $RunEnd.ToString('zzz')

$css = @'
:root{--ink:#1b2430;--muted:#5b6675;--line:#e3e7ec;--bg:#f5f7fa;--card:#ffffff;--brand:#0b2545;--accent:#0f766e;
--ok:#137333;--okbg:#e6f4ea;--warn:#8a5a00;--warnbg:#fef4d8;--miss:#b3261e;--missbg:#fce8e6;--nc:#5f6368;--ncbg:#eef0f2}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
header{background:var(--brand);color:#fff;padding:28px 0 24px}
.brand{font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.85}
.brand b{font-weight:700;letter-spacing:.02em}
h1{margin:6px 0 14px;font-size:28px;font-weight:600;letter-spacing:-.01em}
.meta{display:flex;flex-wrap:wrap;gap:8px 28px;font-size:13px;opacity:.95}
.meta span{color:#b9c6d8;margin-right:6px}
.ro{margin:18px 0 0;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);border-radius:8px;padding:10px 14px;font-size:13px}
main{padding:24px 0 8px}
h2{font-size:18px;margin:32px 0 12px;font-weight:600}
h3{font-size:15px;margin:0;font-weight:600}
.tally{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 16px}
.tally div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:150px}
.tally b{font-size:22px;display:block;line-height:1.2}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--nc);border-radius:8px;padding:14px 16px;break-inside:avoid}
.card.st-ready{border-left-color:var(--ok)}.card.st-action{border-left-color:#d08a00}.card.st-na{border-left-color:#9aa0a6}
.card .n{font-size:12px;color:var(--muted)}
.card p{margin:8px 0 0;color:var(--muted);font-size:13px}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;white-space:nowrap}
.pill.st-ready,.pill.it-ok{background:var(--okbg);color:var(--ok)}
.pill.st-action,.pill.it-warn{background:var(--warnbg);color:var(--warn)}
.pill.it-miss{background:var(--missbg);color:var(--miss)}
.pill.st-na,.pill.it-nc{background:var(--ncbg);color:var(--nc)}
.cardhead{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:6px}
a.card{display:block;color:inherit;text-decoration:none}a.card:hover{border-color:#c5ccd6}
ol.actions{list-style:none;padding:0;margin:0;counter-reset:a;background:var(--card);border:1px solid var(--line);border-radius:8px}
ol.actions li{display:grid;grid-template-columns:22px 1fr auto;gap:12px;align-items:start;padding:12px 16px;border-top:1px solid var(--line);break-inside:avoid}
ol.actions li:first-child{border-top:0}
.box{width:16px;height:16px;border:1.5px solid #8a94a3;border-radius:3px;margin-top:3px}
.role{font-size:12px;color:var(--accent);background:#e6f2f1;border-radius:6px;padding:2px 8px;white-space:nowrap}
.pri{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
section.mod{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px 20px;margin:0 0 14px}
.modhead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:4px}
.sub{color:var(--muted);font-size:13px;margin:0 0 12px}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0 4px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line);padding:6px 8px;background:#fafbfc}
td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}
td.c-st{width:1%;white-space:nowrap}
td.c-who{color:var(--muted);font-size:12px;width:18%}
h4{font-size:13px;margin:16px 0 4px;font-weight:600}
.note{color:var(--muted);font-size:12px;margin:4px 0 0}
.not ul{margin:0;padding-left:18px}.not li{margin:4px 0}
.not{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 20px}
footer{margin:28px 0 0;padding:18px 0 36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
footer b{color:var(--ink)}
@media print{body{background:#fff;font-size:12px}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
.pill,.card,.role{-webkit-print-color-adjust:exact;print-color-adjust:exact}section.mod{break-inside:auto}h2{break-after:avoid}.wrap{max-width:none}}
@media (max-width:640px){.wrap{padding:0 16px}h1{font-size:22px}ol.actions li{grid-template-columns:22px 1fr}ol.actions li .role{grid-column:2}}
'@

$CellPill = @{
    'Granted' = 'it-ok'; 'Not granted' = 'it-miss'; 'App not created yet' = 'it-miss'; 'Not requested (optional)' = 'it-nc'
    'Valid' = 'it-ok'; 'Expired' = 'it-miss'; 'Expires within 30 days' = 'it-warn'
    'Enabled' = 'it-ok'; 'Disabled' = 'it-miss'; 'Not found' = 'it-warn'; 'not permitted' = 'it-nc'
}
$sb = New-Object System.Text.StringBuilder
function Add-G360Html { param([string]$Text) [void]$sb.Append($Text) }

Add-G360Html '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
Add-G360Html ('<title>Govern360 Pre-POC Readiness - ' + (ConvertTo-G360Html $DomainLabel) + '</title><style>' + $css + '</style></head><body>')
Add-G360Html '<header><div class="wrap"><div class="brand"><b>Govern360</b> by AIVONS</div><h1>Pre-POC readiness report</h1><div class="meta">'
Add-G360Html ('<div><span>Tenant</span>' + (ConvertTo-G360Html $DomainLabel) + '</div>')
Add-G360Html ('<div><span>Tenant ID</span>' + (ConvertTo-G360Html $S.TenantId) + '</div>')
Add-G360Html ('<div><span>Run</span>' + (ConvertTo-G360Html ($RunEnd.ToString('yyyy-MM-dd HH:mm') + ' (UTC' + $tz + ')')) + '</div>')
Add-G360Html ('<div><span>Run by</span>' + (ConvertTo-G360Html $runBy) + '</div></div>')
Add-G360Html '<div class="ro"><b>Read-only.</b> This check only read your tenant. It created no apps, secrets, role assignments or consent grants and changed no settings. The report contains counts, role names and the names of environments, capacities and subscriptions - no user names from usage reports and no secret values.</div>'
Add-G360Html '</div></header><main class="wrap">'

Add-G360Html '<h2>Readiness summary</h2><div class="tally">'
Add-G360Html ('<div><b style="color:var(--ok)">' + $counts['Ready'] + '</b>Ready</div>')
Add-G360Html ('<div><b style="color:var(--warn)">' + $counts['Needs action'] + '</b>Needs action</div>')
Add-G360Html ('<div><b style="color:var(--nc)">' + $counts['Not available'] + '</b>Not available</div>')
Add-G360Html ('<div><b>' + @($SortedActions).Count + '</b>Actions before the POC</div></div><div class="grid">')
foreach ($md in $ModuleDefs) {
    $st = $ModuleState[$md.key]
    $cls = 'st-na'; if ($st.status -eq 'Ready') { $cls = 'st-ready' } elseif ($st.status -eq 'Needs action') { $cls = 'st-action' }
    Add-G360Html ('<a class="card ' + $cls + '" href="#m-' + $md.key + '"><div class="cardhead"><span class="n">' + $md.n + ' of 10</span><span class="pill ' + $cls + '">' + (ConvertTo-G360Html $st.status) + '</span></div><h3>' + (ConvertTo-G360Html $md.label) + '</h3><p>' + (ConvertTo-G360Html $st.summary) + '</p></a>')
}
Add-G360Html '</div>'

Add-G360Html '<h2>Action checklist</h2>'
if (@($SortedActions).Count -eq 0) { Add-G360Html '<p>Nothing to do before the POC.</p>' }
else {
    Add-G360Html '<ol class="actions">'
    foreach ($a in $SortedActions) {
        $ml = ($ModuleDefs | Where-Object { $_.key -eq $a.module } | Select-Object -First 1).label
        $pl = 'Recommended'; if ($a.priority -eq 1) { $pl = 'Required' } elseif ($a.priority -ge 3) { $pl = 'Optional' }
        Add-G360Html ('<li><div class="box"></div><div><div>' + (ConvertTo-G360Html $a.text) + '</div><div class="pri">' + (ConvertTo-G360Html ($pl + ' - ' + $ml)) + '</div></div><span class="role">' + (ConvertTo-G360Html $a.role) + '</span></li>')
    }
    Add-G360Html '</ol>'
}

Add-G360Html '<h2>Details by module</h2>'
foreach ($md in $ModuleDefs) {
    $st = $ModuleState[$md.key]
    $cls = 'st-na'; if ($st.status -eq 'Ready') { $cls = 'st-ready' } elseif ($st.status -eq 'Needs action') { $cls = 'st-action' }
    Add-G360Html ('<section class="mod" id="m-' + $md.key + '"><div class="modhead"><h3>' + $md.n + '. ' + (ConvertTo-G360Html $md.label) + '</h3><span class="pill ' + $cls + '">' + (ConvertTo-G360Html $st.status) + '</span></div><p class="sub">' + (ConvertTo-G360Html $md.sub) + '</p>')
    $items = @($Results | Where-Object { $_.module -eq $md.key })
    if (@($items).Count -gt 0) {
        Add-G360Html '<div class="tw"><table><thead><tr><th>Check</th><th>Result</th><th>Detail</th><th>Who can fix it</th></tr></thead><tbody>'
        foreach ($it in $items) {
            Add-G360Html ('<tr><td>' + (ConvertTo-G360Html $it.check) + '</td><td class="c-st"><span class="pill ' + (Get-G360StatusClass $it.status) + '">' + (ConvertTo-G360Html (Get-G360StatusLabel $it.status)) + '</span></td><td>' + (ConvertTo-G360Html $it.detail) + '</td><td class="c-who">' + (ConvertTo-G360Html $it.who_can_fix) + '</td></tr>')
        }
        Add-G360Html '</tbody></table></div>'
    }
    foreach ($t in @($Tables | Where-Object { $_.module -eq $md.key })) {
        Add-G360Html ('<h4>' + (ConvertTo-G360Html $t.title) + '</h4><div class="tw"><table><thead><tr>')
        foreach ($c in $t.columns) { Add-G360Html ('<th>' + (ConvertTo-G360Html $c) + '</th>') }
        Add-G360Html '</tr></thead><tbody>'
        foreach ($r in @($t.rows)) {
            Add-G360Html '<tr>'
            foreach ($cell in @($r)) {
                $pc = $null
                if ($null -ne $cell -and $CellPill.ContainsKey([string]$cell)) { $pc = $CellPill[[string]$cell] }
                if ($pc) { Add-G360Html ('<td><span class="pill ' + $pc + '">' + (ConvertTo-G360Html $cell) + '</span></td>') }
                else { Add-G360Html ('<td>' + (ConvertTo-G360Html $cell) + '</td>') }
            }
            Add-G360Html '</tr>'
        }
        Add-G360Html '</tbody></table></div>'
        if ($t.note) { Add-G360Html ('<p class="note">' + (ConvertTo-G360Html $t.note) + '</p>') }
    }
    Add-G360Html '</section>'
}

Add-G360Html '<h2>What this script did NOT do</h2><div class="not"><ul>'
foreach ($line in @(
        'It made no changes to your tenant: no app registrations, service principals, secrets, certificates, role assignments, consent grants or setting changes.',
        'It used only read calls (HTTP GET). The one exception is the Azure Cost Management query, which Microsoft exposes as a POST but which only reads a 7-day cost total.',
        'It exported no data except counts, role names, SKU names, and the names of Power Platform environments, Fabric capacities, Azure subscriptions and Govern360 apps.',
        'It kept no user names from usage reports - the Copilot usage report is reduced to counts in memory.',
        'It read no secret or certificate values - only their names and expiry dates.',
        'It read no mail, files, chats, Copilot prompts or answers, or audit records.',
        'It printed, logged and saved no access tokens; they were held in memory and cleared at the end.',
        'It sent nothing to Govern360 or AIVONS. The report and JSON file stay on this machine until you choose to share them.'
    )) { Add-G360Html ('<li>' + (ConvertTo-G360Html $line) + '</li>') }
if ($S.GraphMode -eq 'mg') { Add-G360Html '<li>Sign-in used Microsoft Graph PowerShell with delegated read scopes only. If Microsoft asked you to consent, that consent was to Microsoft&#39;s own PowerShell app, not to Govern360.</li>' }
Add-G360Html '</ul></div>'
Add-G360Html ('<footer><b>Prepared for your Govern360 proof of concept.</b><br>Govern360 by AIVONS - Pre-POC readiness check v' + $G360ToolVersion + '. Generated ' + (ConvertTo-G360Html ($RunEnd.ToString('yyyy-MM-dd HH:mm') + ' UTC' + $tz)) + ' in ' + [int]($RunEnd - $G360RunStart).TotalSeconds + ' s.</footer>')
Add-G360Html '</main></body></html>'

$enc = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($HtmlPath, $sb.ToString(), $enc)

$jsonObj = [ordered]@{
    tool = 'Govern360 Pre-POC readiness check'; brand = 'Govern360 by AIVONS'; version = $G360ToolVersion
    read_only = 'Read-only: GET calls only, plus the Azure Cost Management read-only query. No tenant changes, no tokens saved.'
    generated = $RunEnd.ToString('o'); run_by = $runBy
    tenant = [ordered]@{ id = $S.TenantId; default_domain = $S.Domain; name = $S.OrgName }
    graph_permissions_default = $DefaultScopes
    modules = @($ModuleDefs | ForEach-Object { [ordered]@{ key = $_.key; label = $_.label; status = $ModuleState[$_.key].status; summary = $ModuleState[$_.key].summary } })
    actions = @($SortedActions)
    checks = @($Results)
    tables = @($Tables | ForEach-Object { [ordered]@{ module = $_.module; title = $_.title; columns = $_.columns; rows = @($_.rows | ForEach-Object { , @($_) }); note = $_.note } })
}
[IO.File]::WriteAllText($JsonPath, ($jsonObj | ConvertTo-Json -Depth 8), $enc)

Write-Host ''
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host (' Ready: {0}   Needs action: {1}   Not available: {2}   Actions: {3}' -f $counts['Ready'], $counts['Needs action'], $counts['Not available'], @($SortedActions).Count) -ForegroundColor Cyan
Write-Host ' Report: ' -NoNewline; Write-Host $HtmlPath -ForegroundColor Green
Write-Host ' JSON:   ' -NoNewline; Write-Host $JsonPath -ForegroundColor Green
if ($IsCloudShell) {
    Write-Host ''
    Write-Host ' Download the report from Cloud Shell with:' -ForegroundColor Cyan
    Write-Host ('   download ' + $HtmlPath)
}
Write-Host '==================================================================' -ForegroundColor Cyan
exit 0
