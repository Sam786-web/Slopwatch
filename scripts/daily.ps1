# Local daily run: continue the harvest within free quotas, check names, run the watchtower,
# rebuild the dashboard and (if a GitHub remote is set up) publish it.
# Register once with Windows Task Scheduler (run in PowerShell):
#   schtasks /Create /SC DAILY /ST 09:00 /TN SlopWatch /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\samiy\slopwatch\scripts\daily.ps1"
Set-Location $PSScriptRoot\..
$log = "data\daily.log"
"=== $(Get-Date -Format s) ===" | Out-File -Append -Encoding utf8 $log
foreach ($step in @("harvest", "check", "watch", "site")) {
    python -m uv run slopwatch $step 2>&1 | Out-File -Append -Encoding utf8 $log
}
if (git remote) {
    git pull --rebase --autostash 2>&1 | Out-File -Append -Encoding utf8 $log
    git add docs data/watchlist.json.enc data/alerts.json.enc
    git diff --cached --quiet
    if ($LASTEXITCODE -ne 0) {
        git commit -m "data: daily dashboard update $(Get-Date -Format yyyy-MM-dd)" 2>&1 | Out-File -Append -Encoding utf8 $log
        git push 2>&1 | Out-File -Append -Encoding utf8 $log
    }
}
