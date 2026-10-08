# =====================================================================
# Govern360 AI inventory - automatic on this computer
#
# An Intune platform script. Runs once per device, as SYSTEM, and makes
# the Govern360 AI inventory run by itself from then on:
#
#   1. Saves the collector to C:\ProgramData\Govern360\Govern360-Collect.ps1
#      (administrators may change it; users may only read and run it).
#   2. Adds the scheduled task \Govern360\Govern360 AI inventory, which
#      runs the collector for whoever is signed in: 5 minutes after
#      sign-in, and every day at 12:30 (or as soon as the computer is on).
#   3. Starts it once now, if someone is signed in.
#
# Nothing to fill in. The organisation's enrollment token is read from the
# Govern360 guard policy already on the computer, so deploy the guard to
# the same devices. The collector is read-only: it records the NAMES of AI
# apps, AI browser extensions, MCP servers, local models and API key
# variables - never prompts, documents, URLs or any key value.
#
# INTUNE
#   Devices > Scripts and remediations > Platform scripts > Add > Windows 10 and later
#     Script: this file
#     Run this script using the logged on credentials: No
#     Enforce script signature check: No
#     Run script in 64 bit PowerShell Host: Yes
#   Assign it to the same devices or groups as the Govern360 guard.
#
# BY HAND (one computer, as administrator):
#   powershell -ExecutionPolicy Bypass -File .\Govern360-AI-Inventory-Intune.ps1
#
# TO REMOVE
#   Unregister-ScheduledTask -TaskPath '\Govern360\' -TaskName 'Govern360 AI inventory' -Confirm:$false
#   Remove-Item "$env:ProgramData\Govern360" -Recurse -Force
# =====================================================================
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:ProgramData 'Govern360'
$file = Join-Path $dir 'Govern360-Collect.ps1'
$taskPath = '\Govern360\'
$taskName = 'Govern360 AI inventory'

$collector = @'
# =====================================================================
# Govern360 endpoint AI inventory collector
#
# Finds the AI on a Windows desktop and reports it to your Govern360
# tenant. Runs once and exits. Starts no service.
#
# WHAT IT COLLECTS
#   - AI applications installed on this machine, including per-user
#     installs that appear in no machine-wide inventory
#   - AI browser extensions, in every installed browser and profile
#   - Local MCP servers configured for Claude Desktop, Cursor, VS Code
#     and Windsurf - server names and argument NAMES only
#   - Local models held by Ollama, LM Studio and GPT4All
#
# WHAT IT NEVER COLLECTS, and this list is the point
#   - No prompts, conversations, messages or documents
#   - No browsing history, no URLs, no page titles
#   - No API key values. Not the value, not a hash, not a prefix
#   - No MCP argument values - the key is read, the value discarded
#   - No file contents, no clipboard, no keystrokes, no screen
#
# It prints the same list when it runs, so the person at the keyboard
# can see what was taken rather than being told.
#
# REQUIRES no administrator rights. Reads only the current user's
# profile plus machine-wide uninstall keys, which are world-readable.
#
# USAGE
#   .\Govern360-Collect.ps1                            # token from the guard policy on this computer
#   .\Govern360-Collect.ps1 -Token <enrollment-token>
#   .\Govern360-Collect.ps1 -WhatIf                    # show, send nothing
#
# 1.1.0 - no token needs typing: when -Token is not given, the
# organisation's enrollment token is read from the Govern360 guard policy
# that is already on this computer (Chrome or Edge, machine or user
# policy). The result of each run is written to
# %LOCALAPPDATA%\Govern360\collect-last.txt. Collection is unchanged.
#
# The enrollment token is minted on the Govern360 Deploy page. It is
# tenant-scoped, grants no read access, and is revocable - the worst a
# leaked token allows is submitting noise to one tenant.
# =====================================================================

[CmdletBinding()]
param(
  [string] $Token = '',
  [string] $ApiBase = 'https://uvurknrcibsikiptmxis.supabase.co',
  [string] $AnonKey = 'sb_publishable_FQcf2g99OR9sQX7Ua9uWMQ_SgOTkrEw',
  [switch] $WhatIf
)

$ErrorActionPreference = 'Stop'
$CollectorVersion = '1.1.0'

# Where the result of the last run is written, for whoever checks this machine.
$LogDir = Join-Path $env:LOCALAPPDATA 'Govern360'
function Write-RunLog([string]$Result) {
  try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $line = (Get-Date).ToString('o') + '  ' + $env:COMPUTERNAME + '  ' + $env:USERNAME + '  v' + $CollectorVersion + '  ' + $Result
    [IO.File]::WriteAllText((Join-Path $LogDir 'collect-last.txt'), $line + "`r`n")
  } catch { }
}

# 1.1.0 - the token the Govern360 guard policy already put on this computer.
if ([string]::IsNullOrWhiteSpace($Token)) {
  $GuardId = 'icihfapoaepjmgidjpgmlgnjkcbjbmgj'
  foreach ($b in @('Google\Chrome', 'Microsoft\Edge')) {
    foreach ($hive in @('HKLM', 'HKCU')) {
      if (-not [string]::IsNullOrWhiteSpace($Token)) { continue }
      $pk = $hive + ':\SOFTWARE\Policies\' + $b + '\3rdparty\extensions\' + $GuardId + '\policy'
      if (Test-Path $pk) {
        $v = (Get-ItemProperty $pk -ErrorAction SilentlyContinue).enrollment_token
        if ($v) { $Token = [string]$v }
      }
    }
  }
}
if ([string]::IsNullOrWhiteSpace($Token)) {
  Write-Host 'No Govern360 enrollment token on this computer and none given with -Token.' -ForegroundColor Red
  Write-Host 'Deploy the Govern360 guard to this computer first (Endpoint Governance > Deploy the guard), or pass -Token.'
  Write-RunLog 'not sent: no enrollment token on this computer'
  exit 3
}

# Each source records its own outcome: ok, empty, or the error. A scan
# that failed must never be indistinguishable from a scan that found
# nothing - that difference is the whole reason the run row exists.
$Sources = @{}
$Items   = New-Object System.Collections.ArrayList

function Add-Item {
  param([string]$Kind, [string]$Key, [string]$Name, [string]$Vendor, [string]$Version, [hashtable]$Detail)
  if ([string]::IsNullOrWhiteSpace($Key)) { return }
  [void]$Items.Add([pscustomobject]@{
    kind = $Kind; key = $Key; name = $Name; vendor = $Vendor
    version = $Version; detail = ($Detail | ForEach-Object { $_ })
  })
}

function Set-Source {
  param([string]$Name, [int]$Found, $Err)
  if ($Err) { $Sources[$Name] = ('error: ' + $Err.ToString().Split("`n")[0]) }
  elseif ($Found -eq 0) { $Sources[$Name] = 'empty' }
  else { $Sources[$Name] = 'ok' }
}

# ---------------------------------------------------------------------
# The catalogue. Matching is on name, so it is deliberately generous -
# a false positive is a row somebody dismisses in triage, a false
# negative is an agent nobody ever hears about.
# ---------------------------------------------------------------------
$AppPatterns = @(
  @{ m = 'ChatGPT';        v = 'OpenAI' },
  @{ m = 'Claude';         v = 'Anthropic' },
  @{ m = 'Cursor';         v = 'Anysphere' },
  @{ m = 'Windsurf';       v = 'Codeium' },
  @{ m = 'Ollama';         v = 'Ollama' },
  @{ m = 'LM Studio';      v = 'LM Studio' },
  @{ m = 'GPT4All';        v = 'Nomic' },
  @{ m = 'Jan';            v = 'Jan' },
  @{ m = 'Msty';           v = 'Msty' },
  @{ m = 'AnythingLLM';    v = 'Mintplex' },
  @{ m = 'Perplexity';     v = 'Perplexity' },
  @{ m = 'Copilot';        v = 'Microsoft' },
  @{ m = 'Tabnine';        v = 'Tabnine' },
  @{ m = 'Continue';       v = 'Continue' },
  @{ m = 'Pieces';         v = 'Pieces' },
  @{ m = 'Raycast';        v = 'Raycast' }
)

$ExtPatterns = @(
  'chatgpt','openai','claude','anthropic','gemini','bard','copilot','perplexity',
  'monica','sider','merlin','harpa','maxai','compose ai','jasper','writesonic',
  'grammarly','quillbot','wordtune','otter','fireflies','tactiq','glasp',
  'chatsonic','youchat','poe','character','codeium','tabnine','blackbox','ai '
)

# =====================================================================
# 1. Installed applications
# =====================================================================
try {
  $found = 0
  $roots = @(
    @{ p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';            s = 'machine' },
    @{ p = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; s = 'machine' },
    @{ p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';            s = 'user' }
  )
  foreach ($r in $roots) {
    Get-ItemProperty $r.p -ErrorAction SilentlyContinue | ForEach-Object {
      $dn = $_.DisplayName
      if (-not $dn) { return }
      foreach ($p in $AppPatterns) {
        if ($dn -like ('*' + $p.m + '*')) {
          Add-Item -Kind 'app' -Key ($p.m.ToLower() + '|' + $r.s) -Name $dn -Vendor $p.v `
                   -Version $_.DisplayVersion `
                   -Detail @{ scope = $r.s; installed = $_.InstallDate; source = 'registry' }
          $script:found++
          break
        }
      }
    }
  }

  # Per-user installs with no uninstall key at all. ChatGPT and Cursor
  # both land here by default, so a tool that only reads HKLM reports a
  # clean machine.
  $progDir = Join-Path $env:LOCALAPPDATA 'Programs'
  if (Test-Path $progDir) {
    Get-ChildItem $progDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $dir = $_.Name
      foreach ($p in $AppPatterns) {
        if ($dir -like ('*' + $p.m + '*')) {
          Add-Item -Kind 'app' -Key ($p.m.ToLower() + '|localappdata') -Name $dir -Vendor $p.v `
                   -Detail @{ scope = 'user'; path_present = $true; source = 'localappdata' }
          $script:found++
          break
        }
      }
    }
  }
  # g360-k379 - Store/MSIX installs appear in no uninstall key, machine
  # or user. On Windows 11 that is where ChatGPT and Copilot land, so the
  # collector read a clean machine on the fleet most likely to have them.
  try {
    Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {
      $pn = $_.Name
      foreach ($p in $AppPatterns) {
        if ($pn -like ('*' + $p.m + '*')) {
          Add-Item -Kind 'app' -Key ($p.m.ToLower() + '|msix') -Name $_.Name -Vendor $p.v `
                   -Version ([string]$_.Version) `
                   -Detail @{ scope = 'user'; source = 'msix'; family = [string]$_.PackageFamilyName }
          $script:found++
          break
        }
      }
    }
  } catch { }

  Set-Source 'apps' $found $null
} catch { Set-Source 'apps' 0 $_ }

# =====================================================================
# 2. Browser extensions - every browser, every profile
#
# The layer Prompt Guard cannot report on, because an extension cannot
# enumerate its siblings. Also the layer an enterprise browser misses
# for every browser it did not replace.
# =====================================================================
try {
  $found = 0
  $chromium = @(
    @{ n = 'Chrome';  p = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ n = 'Edge';    p = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
    @{ n = 'Brave';   p = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
    @{ n = 'Vivaldi'; p = "$env:LOCALAPPDATA\Vivaldi\User Data" },
    @{ n = 'Opera';   p = "$env:APPDATA\Opera Software\Opera Stable" }
  )
  foreach ($b in $chromium) {
    if (-not (Test-Path $b.p)) { continue }
    Get-ChildItem $b.p -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' } | ForEach-Object {
        $prof = $_.Name
        $extRoot = Join-Path $_.FullName 'Extensions'
        if (-not (Test-Path $extRoot)) { return }
        Get-ChildItem $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
          $extId = $_.Name
          $man = Get-ChildItem $_.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue |
                 Select-Object -First 1
          if (-not $man) { return }
          try {
            $j = Get-Content $man.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
            $nm = [string]$j.name
            # Localised names come through as __MSG_... and are useless
            # for matching, so the extension id carries the identity.
            $hay = ($nm + ' ' + $extId).ToLower()
            $hit = $false
            foreach ($pat in $ExtPatterns) { if ($hay -like ('*' + $pat + '*')) { $hit = $true; break } }
            if (-not $hit) { return }
            $perms = @()
            if ($j.permissions)      { $perms += $j.permissions }
            if ($j.host_permissions) { $perms += $j.host_permissions }
            # g360-k379 - MV3 moved host access out of `permissions` into
            # `host_permissions` AND `content_scripts[].matches`. Reading only
            # the first two reported Grammarly - which reads and rewrites text
            # on every site - as narrow. A false "no broad access" is the one
            # error this collector must not make.
            $csMatches = @()
            if ($j.content_scripts) {
              foreach ($cs in $j.content_scripts) { if ($cs.matches) { $csMatches += $cs.matches } }
            }
            $allHosts = @($perms) + @($csMatches)
            $broad = ($allHosts -join ' ') -match '<all_urls>|\*://\*/|https://\*/'
            Add-Item -Kind 'extension' -Key ($b.n.ToLower() + ':' + $extId) `
                     -Name $nm -Vendor $b.n -Version ([string]$j.version) `
                     -Detail @{ browser = $b.n; profile = $prof; broad_host_access = $broad
                                content_script_matches = @($csMatches).Count
                                permission_count = $perms.Count }
            $script:found++
          } catch { }
        }
      }
  }

  # Firefox keeps its own inventory in one file per profile.
  $ffRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"
  if (Test-Path $ffRoot) {
    Get-ChildItem $ffRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $f = Join-Path $_.FullName 'extensions.json'
      if (-not (Test-Path $f)) { return }
      $prof = $_.Name
      try {
        $j = Get-Content $f -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($a in $j.addons) {
          if ($a.type -ne 'extension') { continue }
          $nm = [string]$a.defaultLocale.name
          $hay = $nm.ToLower()
          $hit = $false
          foreach ($pat in $ExtPatterns) { if ($hay -like ('*' + $pat + '*')) { $hit = $true; break } }
          if (-not $hit) { continue }
          Add-Item -Kind 'extension' -Key ('firefox:' + [string]$a.id) -Name $nm `
                   -Vendor 'Firefox' -Version ([string]$a.version) `
                   -Detail @{ browser = 'Firefox'; profile = $prof; active = [bool]$a.active }
          $script:found++
        }
      } catch { }
    }
  }
  Set-Source 'extensions' $found $null
} catch { Set-Source 'extensions' 0 $_ }

# =====================================================================
# 3. Local MCP servers
#
# The highest-value signal on a developer machine and invisible to
# everything else. An MCP server is a tool grant made on a laptop, with
# no approval, no owner and no record.
#
# ARGUMENT NAMES ONLY. These files routinely carry API keys and
# connection strings in `env` and `args`. Read the key, discard the
# value, and never transmit either the value or a hash of it.
# =====================================================================
try {
  $found = 0
  $configs = @(
    # g360-k380 - Claude Desktop is expanded below: classic AND container.
    @{ c = 'Cursor';         p = "$env:USERPROFILE\.cursor\mcp.json" },
    @{ c = 'Windsurf';       p = "$env:USERPROFILE\.codeium\windsurf\mcp_config.json" },
    @{ c = 'Continue';       p = "$env:USERPROFILE\.continue\config.json" }
  )
  # g360-k380 - an MSIX app is containerised, so its AppData is redirected
  # into the package folder. %APPDATA%\Claude does not exist on a machine
  # where Claude Desktop was installed from the Store; the config lives at
  # %LOCALAPPDATA%\Packages\<family>\LocalCache\Roaming\Claude\.
  #
  # Every container is enumerated rather than the family name being
  # hard-coded, so this works for ChatGPT or anything else that arrives as
  # MSIX without knowing its identifier in advance.
  $roamingClients = @(
    @{ c = 'Claude Desktop'; rel = 'Claude\claude_desktop_config.json' }
  )
  foreach ($rc in $roamingClients) {
    $classic = Join-Path $env:APPDATA $rc.rel
    if (Test-Path $classic) { $configs += @{ c = $rc.c; p = $classic; pkg = $null } }
    $pkgRoot = Join-Path $env:LOCALAPPDATA 'Packages'
    if (Test-Path $pkgRoot) {
      Get-ChildItem $pkgRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $cp = Join-Path $_.FullName ('LocalCache\Roaming\' + $rc.rel)
        if (Test-Path $cp) { $script:configs += @{ c = $rc.c; p = $cp; pkg = $_.Name } }
      }
    }
  }

  foreach ($cfg in $configs) {
    if (-not (Test-Path $cfg.p)) { continue }
    try {
      $j = Get-Content $cfg.p -Raw -ErrorAction Stop | ConvertFrom-Json
      $servers = $null
      if ($j.mcpServers)   { $servers = $j.mcpServers }
      elseif ($j.mcp)      { $servers = $j.mcp }
      if (-not $servers)   { continue }
      foreach ($name in $servers.PSObject.Properties.Name) {
        $s = $servers.$name
        # Names of env vars, never their values.
        $envNames = @()
        if ($s.env) { $envNames = $s.env.PSObject.Properties.Name }
        Add-Item -Kind 'mcp' -Key ($cfg.c.ToLower().Replace(' ','-') + ':' + $name) `
                 -Name $name -Vendor $cfg.c `
                 -Detail @{ client = $cfg.c; command = [string]$s.command
                            container = $cfg.pkg   # g360-k380
                            arg_count = @($s.args).Count
                            env_names = $envNames
                            note = 'argument and env VALUES are never read' }
        $script:found++
      }
    } catch { }
  }
  Set-Source 'mcp' $found $null
} catch { Set-Source 'mcp' 0 $_ }

# =====================================================================
# 4. Local models
#
# A model running wholly offline is the one thing no network control
# would ever see.
# =====================================================================
try {
  $found = 0
  $stores = @(
    @{ n = 'Ollama';    p = "$env:USERPROFILE\.ollama\models\manifests" },
    @{ n = 'LM Studio'; p = "$env:USERPROFILE\.cache\lm-studio\models" },
    @{ n = 'GPT4All';   p = "$env:LOCALAPPDATA\nomic.ai\GPT4All" }
  )
  foreach ($s in $stores) {
    if (-not (Test-Path $s.p)) { continue }
    Get-ChildItem $s.p -Recurse -File -ErrorAction SilentlyContinue |
      Select-Object -First 200 | ForEach-Object {
        if ($_.Length -lt 1MB -and $s.n -ne 'Ollama') { return }
        Add-Item -Kind 'model' -Key ($s.n.ToLower() + ':' + $_.Name) -Name $_.Name -Vendor $s.n `
                 -Detail @{ store = $s.n; size_mb = [math]::Round($_.Length / 1MB, 1)
                            modified = $_.LastWriteTime.ToString('o') }
        $script:found++
      }
  }
  Set-Source 'models' $found $null
} catch { Set-Source 'models' 0 $_ }

# =====================================================================
# 5. API key presence - NAMES ONLY
#
# The fact a variable exists and what it is called. A governance tool
# that exfiltrates a secret has become the incident it was deployed to
# prevent.
# =====================================================================
try {
  $found = 0
  Get-ChildItem Env: -ErrorAction SilentlyContinue | ForEach-Object {
    $n = $_.Name
    if ($n -match '(?i)(OPENAI|ANTHROPIC|GEMINI|GOOGLE_AI|MISTRAL|COHERE|HUGGINGFACE|GROQ|PERPLEXITY|XAI)_|_API_KEY$') {
      Add-Item -Kind 'apikey' -Key $n -Name $n `
               -Detail @{ scope = 'user environment'; note = 'name only; the value is never read' }
      $script:found++
    }
  }
  Set-Source 'apikeys' $found $null
} catch { Set-Source 'apikeys' 0 $_ }

# =====================================================================
# Report, then send
# =====================================================================
$device = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
if (-not $os) { $os = [System.Environment]::OSVersion.VersionString }

Write-Host ''
Write-Host 'Govern360 endpoint inventory' -ForegroundColor Cyan
Write-Host ('Device: ' + $device + '   ' + $os)
Write-Host ''
Write-Host 'Collected:'
$Items | Group-Object kind | Sort-Object Count -Descending | ForEach-Object {
  Write-Host ('  {0,-10} {1}' -f $_.Name, $_.Count)
}
if ($Items.Count -eq 0) { Write-Host '  nothing found' }
Write-Host ''
Write-Host 'Scan results:'
foreach ($k in ($Sources.Keys | Sort-Object)) {
  $v = $Sources[$k]
  $c = if ($v -eq 'ok') { 'Green' } elseif ($v -eq 'empty') { 'Gray' } else { 'Yellow' }
  Write-Host ('  {0,-12} {1}' -f $k, $v) -ForegroundColor $c
}
Write-Host ''
Write-Host 'NOT collected, by design:' -ForegroundColor Cyan
Write-Host '  prompts, conversations, documents, file contents'
Write-Host '  browsing history, URLs, page titles'
Write-Host '  API key values - only the variable NAME is recorded'
Write-Host '  MCP argument and environment VALUES - only their names'
Write-Host '  clipboard, keystrokes, screen'
Write-Host ''

if ($WhatIf) {
  Write-Host 'WhatIf: nothing sent. Payload below.' -ForegroundColor Yellow
  $Items | ConvertTo-Json -Depth 5
  return
}

$body = @{
  p_token             = $Token
  p_device            = $device
  p_os                = $os
  p_collector_version = $CollectorVersion
  p_sources           = $Sources
  p_items             = $Items
} | ConvertTo-Json -Depth 6 -Compress

try {
  # PowerShell 5.1 defaults to TLS 1.0, which Supabase refuses.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $res = Invoke-RestMethod -Method Post -TimeoutSec 60 `
    -Uri ($ApiBase + '/rest/v1/rpc/record_endpoint_inventory_enrolled') `
    -Headers @{ apikey = $AnonKey; Authorization = ('Bearer ' + $AnonKey); 'Content-Type' = 'application/json' } `
    -Body $body

  if ($res.ok -eq $false) {
    # A revoked token is a refusal, not an error. Stop rather than retry.
    Write-Host ('Refused: ' + $res.reason) -ForegroundColor Red
    Write-Host 'The enrollment token is invalid or has been revoked. Generate a new one on the Deploy page.'
    Write-RunLog ('refused: ' + $res.reason)
    exit 2
  }
  Write-Host ('Sent. ' + $Items.Count + ' items recorded for ' + $device + '.') -ForegroundColor Green
  Write-RunLog ('sent: ' + $Items.Count + ' items')
} catch {
  Write-Host ('Send failed: ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host 'Nothing was recorded. This device stays unmeasured rather than reading as clean.'
  Write-RunLog ('send failed: ' + $_.Exception.Message)
  exit 1
}
'@

# 1. The collector, where users can run it but not change it.
New-Item -ItemType Directory -Path $dir -Force | Out-Null
[IO.File]::WriteAllText($file, ($collector -replace "`r?`n", "`r`n"), (New-Object Text.UTF8Encoding $false))
# SYSTEM and Administrators full control; Users read and execute only. SIDs, so any Windows language works.
& icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
Write-Output ('Collector saved: ' + $file)

# 2. The schedule: every signed-in user, 5 minutes after sign-in and daily at 12:30.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $file + '"')
$atLogon = New-ScheduledTaskTrigger -AtLogOn
$atLogon.Delay = 'PT5M'
$daily = New-ScheduledTaskTrigger -Daily -At '12:30'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
try { $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited }
catch { $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited }
Register-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Action $action -Trigger @($atLogon, $daily) -Principal $principal -Settings $settings `
  -Description 'Govern360 AI inventory: records the names of AI apps, AI browser extensions, MCP servers, local models and API key variables on this computer. Never prompts, documents, URLs or key values.' -Force | Out-Null
Write-Output ('Scheduled task: ' + $taskPath + $taskName + ' (at sign-in + 5 min, daily 12:30)')

# 3. Once now, for whoever is signed in.
try { Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName; Write-Output 'Started once now for the signed-in user.' }
catch { Write-Output 'Not started now (no one signed in); it runs at the next sign-in.' }
exit 0
