param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Args
)

 $jar = Join-Path $PSScriptRoot 'static/java/gp.jar'
if (-not (Test-Path $jar)) {
    Write-Error "gp.jar not found at $jar"
    exit 1
}
$staticJava = Get-ChildItem -Path (Join-Path $PSScriptRoot 'static/java/jdk') -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'bin/java.exe') } | Sort-Object Name -Descending | Select-Object -First 1
if ($staticJava) {
    $javaExe = Join-Path $staticJava.FullName 'bin/java.exe'
} else {
    $javaExe = 'java'
}
& $javaExe -jar $jar @Args