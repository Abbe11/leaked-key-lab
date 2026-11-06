<#
  secret-sniffer: finds leaked API keys and private keys in files.
  Prints masked previews only, never the full secret.
  Exit code 1 if anything is found, 0 if clean.
#>
param(
    [string[]]$Path = "."
)

# Folders and file types that are noise, not your code
$skipDirs = '\\(\.git|\.venv|venv|node_modules|target|__pycache__)\\'
$skipExt  = '.jar','.pyc','.exe','.dll','.zip','.png','.jpg','.gif','.pdf'

# Key shapes: prefix plus a minimum length, so ordinary words don't match
$patterns = [ordered]@{
    'Groq API key'        = 'gsk_[A-Za-z0-9]{20,}'
    'OpenAI-style key'    = '\bsk-[A-Za-z0-9_-]{20,}'
    'GitHub token'        = 'gh[pousr]_[A-Za-z0-9]{30,}'
    'GitHub fine-grained' = 'github_pat_[A-Za-z0-9_]{30,}'
    'AWS access key'      = '\bAKIA[0-9A-Z]{16}\b'
    'Private key'         = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
}

# -Force includes hidden files like .env
$files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skipDirs -and $skipExt -notcontains $_.Extension.ToLower() }

$findings = foreach ($file in $files) {
    foreach ($name in $patterns.Keys) {
        $hits = Select-String -Path $file.FullName -Pattern $patterns[$name] -AllMatches -ErrorAction SilentlyContinue
        foreach ($hit in $hits) {
            foreach ($m in $hit.Matches) {
                [PSCustomObject]@{
                    File    = $file.FullName
                    Line    = $hit.LineNumber
                    Type    = $name
                    Preview = $m.Value.Substring(0, [Math]::Min(8, $m.Value.Length)) + '****'
                }
            }
        }
    }
}

if ($findings) {
    $findings | Format-Table -Wrap
    Write-Host "$(@($findings).Count) possible secret(s) found. Triage each one." -ForegroundColor Red
    exit 1
} else {
    Write-Host "No secrets found." -ForegroundColor Green
    exit 0
}
