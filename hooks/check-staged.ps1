# Scan only the files that are about to be committed
$files = git diff --cached --name-only --diff-filter=ACM
if (-not $files) { exit 0 }

& "$PSScriptRoot\..\secret-sniffer.ps1" -Path $files
if ($LASTEXITCODE -ne 0) {
    Write-Host "COMMIT BLOCKED: remove the secret, then commit again." -ForegroundColor Red
    exit 1
}
exit 0
