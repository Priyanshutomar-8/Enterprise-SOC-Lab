# Lab 02c - lint Sentinel analytics-rule YAML files before they are imported.
# PowerShell 5.1 has no YAML parser, so this is a line-based checker for the fields and
# limits that cause an import failure or a silently broken rule. It is NOT Microsoft's
# schema validator (Azure-Sentinel repo CI) - a pass here is a pre-check, not proof.
#
#   .\Lab02c-lint.ps1                     # all *.yaml under .\Lab02c-rules
#   .\Lab02c-lint.ps1 -Path .\some.yaml
param([string]$Path = (Join-Path $PSScriptRoot 'Lab02c-rules'))

$required = 'id', 'name', 'description', 'severity', 'requiredDataConnectors', 'queryFrequency',
    'queryPeriod', 'triggerOperator', 'triggerThreshold', 'tactics', 'relevantTechniques',
    'query', 'entityMappings', 'version', 'kind'
$tacticsOk = 'Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution', 'Persistence',
    'PrivilegeEscalation', 'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement',
    'Collection', 'Exfiltration', 'CommandAndControl', 'Impact'

function ConvertTo-Span([string]$s) {
    if ($s -notmatch '^(\d+)([mhd])$') { return $null }
    $n = [int]$Matches[1]
    switch ($Matches[2]) {
        'm' { [timespan]::FromMinutes($n) }
        'h' { [timespan]::FromHours($n) }
        'd' { [timespan]::FromDays($n) }
    }
}

# Lines of the block that starts at top-level key $key (indented lines until next top-level key).
function Get-Block([string[]]$lines, [string]$key) {
    $out = @(); $in = $false
    foreach ($l in $lines) {
        if ($l -match "^$key\s*:") { $in = $true; continue }
        if ($in) { if ($l -match '^\S') { break }; $out += $l }
    }
    return $out
}

function Get-Value([string[]]$lines, [string]$key) {
    $l = $lines | Where-Object { $_ -match "^$key\s*:" } | Select-Object -First 1
    if ($l) { return (($l -replace "^$key\s*:\s*", '').Trim().Trim('"')) }
}

$files = if (Test-Path $Path -PathType Container) { Get-ChildItem $Path -Filter *.yaml } else { Get-Item $Path }
$ids = @{}
$failed = 0

foreach ($f in $files) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw
    $lines = Get-Content -LiteralPath $f.FullName
    $errs = New-Object System.Collections.Generic.List[string]
    $warns = New-Object System.Collections.Generic.List[string]

    foreach ($k in $required) {
        if (-not ($lines -match "^$k\s*:")) { $errs.Add("missing required key '$k'") }
    }
    if ($raw -match "`t") { $errs.Add('contains a TAB character (YAML forbids tabs for indentation)') }

    $id = Get-Value $lines 'id'
    if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $errs.Add("id '$id' is not a GUID")
    } elseif ($ids.ContainsKey($id)) {
        $errs.Add("id duplicates $($ids[$id])")
    } else { $ids[$id] = $f.Name }

    $sev = Get-Value $lines 'severity'
    if ($sev -cnotin 'Informational', 'Low', 'Medium', 'High') { $errs.Add("severity '$sev' invalid") }
    if ((Get-Value $lines 'kind') -cne 'Scheduled') { $errs.Add("kind is not 'Scheduled'") }
    if ((Get-Value $lines 'version') -notmatch '^\d+\.\d+\.\d+$') { $errs.Add('version is not x.y.z') }
    if ((Get-Value $lines 'triggerOperator') -notin 'gt', 'lt', 'eq') { $errs.Add('triggerOperator not gt/lt/eq') }

    $freq = ConvertTo-Span (Get-Value $lines 'queryFrequency')
    $per = ConvertTo-Span (Get-Value $lines 'queryPeriod')
    if (-not $freq -or -not $per) { $errs.Add('queryFrequency/queryPeriod not in <n>m|h|d form') }
    else {
        if ($freq -lt [timespan]::FromMinutes(5) -or $freq -gt [timespan]::FromDays(14)) { $errs.Add('queryFrequency outside 5m..14d') }
        if ($per -lt [timespan]::FromMinutes(5) -or $per -gt [timespan]::FromDays(14)) { $errs.Add('queryPeriod outside 5m..14d') }
        if ($per -lt $freq) { $errs.Add('queryPeriod shorter than queryFrequency - events between runs are never queried') }
    }

    foreach ($t in (Get-Block $lines 'tactics' | ForEach-Object { if ($_ -match '^\s*-\s*(\S+)') { $Matches[1] } })) {
        if ($t -cnotin $tacticsOk) { $errs.Add("unknown tactic '$t'") }
    }
    foreach ($t in (Get-Block $lines 'relevantTechniques' | ForEach-Object { if ($_ -match '^\s*-\s*(\S+)') { $Matches[1] } })) {
        if ($t -notmatch '^T\d{4}(\.\d{3})?$') { $errs.Add("technique '$t' is not Txxxx or Txxxx.yyy") }
    }

    $query = (Get-Block $lines 'query') -join "`n"
    if ($query.Length -gt 10000) { $errs.Add("query is $($query.Length) chars; Sentinel limit is 10000") }

    # Every column the rule maps or displays must be produced by the query. Case-sensitive:
    # KQL column names are, and PowerShell's -match is not (caught by the SrcIP negative test).
    $cols = @()
    $cols += Get-Block $lines 'entityMappings' | ForEach-Object { if ($_ -match 'columnName:\s*(\S+)') { $Matches[1] } }
    $cols += Get-Block $lines 'customDetails' | ForEach-Object { if ($_ -match '^\s+\w+:\s*(\S+)') { $Matches[1] } }
    $ado = (Get-Block $lines 'alertDetailsOverride') -join "`n"
    $cols += [regex]::Matches($ado, '\{\{(\w+)\}\}') | ForEach-Object { $_.Groups[1].Value }
    $cols += Get-Block $lines 'alertDetailsOverride' | ForEach-Object { if ($_ -match 'alertSeverityColumnName:\s*(\S+)') { $Matches[1] } }
    foreach ($c in ($cols | Select-Object -Unique)) {
        if ($query -cnotmatch "\b$([regex]::Escape($c))\b") { $errs.Add("column '$c' is mapped/displayed but never appears in the query") }
    }
    $nEnt = @(Get-Block $lines 'entityMappings' | Where-Object { $_ -match '^\s*-\s*entityType:' }).Count
    if ($nEnt -gt 10) { $errs.Add("$nEnt entity mappings; limit is 10") }
    $nCd = @(Get-Block $lines 'customDetails' | Where-Object { $_ -match '^\s+\w+:' }).Count
    if ($nCd -gt 20) { $errs.Add("$nCd custom details; limit is 20") }

    # House rule from Lab 02: windowing on event time alone silently drops late/mis-dated events.
    if ($query -notmatch 'ingestion_time\(\)') { $warns.Add('query never uses ingestion_time() - late or mis-dated events can fall between runs (Lab 02)') }

    if ($errs.Count) {
        $failed++
        Write-Output "FAIL  $($f.Name)"
        $errs | ForEach-Object { Write-Output "      - $_" }
    } else { Write-Output "PASS  $($f.Name)" }
    $warns | ForEach-Object { Write-Output "      warn: $_" }
}
Write-Output ("{0} file(s), {1} failed" -f @($files).Count, $failed)
if ($failed) { exit 1 }
