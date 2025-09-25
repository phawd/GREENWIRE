param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Args
)

$jar = Join-Path $PSScriptRoot 'static/java/gp.jar'
if (-not (Test-Path $jar)) {
    Write-Error "gp.jar not found at $jar"
    exit 1
}
& java -jar $jar @Args