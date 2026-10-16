# Lab 02c - render a Sentinel analytics-rule YAML into an ADX test harness.
# Takes the rule's query block VERBATIM, swaps ingestion_time() for the shim's _Ingest
# column (the only edit), and wraps it in a shim that replays one scheduled run.
#
# Example:
#   .\Lab02c-render.ps1 -Rule .\Lab02c-rules\kerberoasting-rc4-user-spn.yaml `
#       -Shim .\Lab02c-shims\kerberos-columns.kql -RunAt 2026-08-28T20:00:00Z
# The harness is printed and copied to the clipboard; paste it into the ADX query editor.
param(
    [Parameter(Mandatory = $true)] [string]$Rule,
    [Parameter(Mandatory = $true)] [string]$Shim,
    [Parameter(Mandatory = $true)] [string]$RunAt
)

$lines = Get-Content -LiteralPath $Rule

$qpLine = $lines | Where-Object { $_ -match '^queryPeriod:\s*(\S+)' } | Select-Object -First 1
if (-not $qpLine) { throw "No queryPeriod in $Rule" }
$queryPeriod = ($qpLine -replace '^queryPeriod:\s*', '').Trim()

# Query block = the indented lines after 'query: |', up to the next top-level key.
$query = New-Object System.Collections.Generic.List[string]
$inQuery = $false
foreach ($l in $lines) {
    if ($l -match '^query:\s*\|') { $inQuery = $true; continue }
    if ($inQuery) {
        if ($l -match '^\S') { break }
        $query.Add(($l -replace '^  ', ''))
    }
}
if ($query.Count -eq 0) { throw "No query block in $Rule" }
$queryText = ($query -join "`n").TrimEnd()
$queryText = $queryText.Replace('ingestion_time()', '_Ingest')

$harness = (Get-Content -LiteralPath $Shim -Raw).
    Replace('{{RUNAT}}', $RunAt).
    Replace('{{QUERYPERIOD}}', $queryPeriod).
    Replace('{{QUERY}}', $queryText)

$header = "// HARNESS rule=$(Split-Path $Rule -Leaf) shim=$(Split-Path $Shim -Leaf) RunAt=$RunAt queryPeriod=$queryPeriod`n"
$out = $header + $harness
$out | Set-Clipboard
$out
