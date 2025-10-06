<#
This script finds files under the GREENWIRE directory larger than a threshold (default 75MB),
appends their relative paths to GREENWIRE/.gitignore (if not already present), and optionally
removes them from the git index (without deleting the working copy) so they won't be published.

Usage:
  # Dry run - list large files
  .\ignore_large_files.ps1 -WhatIf

  # Append to .gitignore and untrack from git index
  .\ignore_large_files.ps1 -Apply -Untrack

Parameters:
  -ThresholdMB (int): size threshold in megabytes (default 75)
  -Apply: actually modify .gitignore (default: false)
  -Untrack: when used with -Apply, will run 'git rm --cached' for matched files
  -GitCmd: path to git executable or command name (default 'git')
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [int]$ThresholdMB = 75,
    [switch]$Apply,
    [switch]$Untrack,
    [string]$GitCmd = 'git'
)

$repoRoot = (Resolve-Path "$(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)\.." ).ProviderPath
$greenwireRoot = Join-Path $repoRoot 'GREENWIRE'
$gitignorePath = Join-Path $greenwireRoot '.gitignore'

Write-Host "Searching for files > $ThresholdMB MB under: $greenwireRoot"
$thresholdBytes = $ThresholdMB * 1MB
$largeFiles = Get-ChildItem -Path $greenwireRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt $thresholdBytes }

if ($largeFiles.Count -eq 0) {
    Write-Host "No files larger than $ThresholdMB MB found under GREENWIRE."
    return
}

Write-Host "Found $($largeFiles.Count) large file(s):"
$largeFiles | Sort-Object Length -Descending | Select-Object FullName, @{Name='SizeMB';Expression={[math]::Round($_.Length/1MB,2)}} | Format-Table -AutoSize

if (-not $Apply) {
    Write-Host "Run with -Apply to append these files to .gitignore and optionally -Untrack to remove them from the git index."
    return
}

# Read existing .gitignore entries
$existing = @()
if (Test-Path $gitignorePath) {
    $existing = Get-Content $gitignorePath -ErrorAction SilentlyContinue
}

$toAdd = @()
foreach ($f in $largeFiles) {
    # Compute path relative to GREENWIRE root
    $rel = Resolve-Path -Relative -Path $f.FullName -RelativeBase $greenwireRoot -ErrorAction SilentlyContinue
    if (-not $rel) {
        # fallback: relative using substring
        $rel = $f.FullName.Substring($greenwireRoot.Length + 1) -replace '\\','/'
    }
    # Use POSIX-style path in .gitignore
    $pattern = "/$rel"
    if ($existing -notcontains $pattern) {
        $toAdd += $pattern
    }
}

if ($toAdd.Count -eq 0) {
    Write-Host "All large files already mentioned in .gitignore."
} else {
    Write-Host "Appending $($toAdd.Count) entries to $gitignorePath"
    Add-Content -Path $gitignorePath -Value "`n# Automatically added large files (>$ThresholdMB MB) on $(Get-Date -Format o)"
    foreach ($line in $toAdd) { Add-Content -Path $gitignorePath -Value $line }
    Write-Host "Appended."
}

if ($Untrack) {
    Write-Host "Removing matched files from git index (git rm --cached)"
    foreach ($f in $largeFiles) {
        $relToRepo = $f.FullName.Substring($repoRoot.Length + 1) -replace '\\','/'
        Write-Host "git rm --cached $relToRepo"
        & $GitCmd rm --cached -- "$relToRepo"
    }
    Write-Host "Files removed from git index. Commit the .gitignore update to finalize."
} else {
    Write-Host "Skipped untracking. Run again with -Untrack to remove these files from the index after reviewing."
}
