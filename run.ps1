param(
    [Parameter(Position=0)]
    [string]$Command = "serve",
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
python -m nexus_iot $Command @Arguments
exit $LASTEXITCODE
