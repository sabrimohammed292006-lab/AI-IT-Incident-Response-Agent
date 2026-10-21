# Uploads this project to the team's GitHub repo.
# Run from the project folder:
#   powershell -ExecutionPolicy Bypass -File .\push_to_github.ps1

$RepoUrl   = "https://github.com/sabrimohammed292006-lab/AI-IT-Incident-Response-Agent.git"
$UserName  = "Besho-y-George"
$UserEmail = "beshoy.besho989@gmail.com"
$Message   = "Add Tools, Data & Safety layer (tools, mock data, guardrails, tickets, tests)"

function Stop-WithError($text) {
    Write-Host ""
    Write-Host "STOPPED: $text" -ForegroundColor Red
    Write-Host "Nothing was uploaded. Send a screenshot of this window to Claude." -ForegroundColor Yellow
    exit 1
}

Set-Location -Path $PSScriptRoot

# 1) Git installed?
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Stop-WithError "Git is not installed. Install it from https://git-scm.com/download/win, then close and reopen Cursor."
}
Write-Host "[1/6] Git found: $(git --version)" -ForegroundColor Green

# 2) Start a git repo here (only the first time)
if (-not (Test-Path ".git")) {
    git init | Out-Null
}
git config user.name  $UserName
git config user.email $UserEmail
Write-Host "[2/6] Git repo ready (author: $UserName)" -ForegroundColor Green

# 3) Add files
git add .
$staged = git diff --cached --name-only
if ($staged | Where-Object { $_ -like ".venv/*" -or $_ -like "*.db" -or $_ -like ".env" }) {
    git reset | Out-Null
    Stop-WithError "Private/local files (.venv, .db or .env) were about to be uploaded."
}
Write-Host "[3/6] Files to upload:" -ForegroundColor Green
$staged | ForEach-Object { Write-Host "      $_" }

# 4) Commit
if ($staged) {
    git commit -m $Message | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Commit failed." }
}
git branch -M main
Write-Host "[4/6] Commit created" -ForegroundColor Green

# 5) Connect to GitHub
$existing = git remote 2>$null
if ($existing -contains "origin") { git remote set-url origin $RepoUrl } else { git remote add origin $RepoUrl }
Write-Host "[5/6] Connected to $RepoUrl" -ForegroundColor Green

# 6) Upload
Write-Host "[6/6] Uploading... (a browser window may open: sign in to GitHub as $UserName and click Authorize)" -ForegroundColor Cyan
git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "Upload was rejected. Your teammate may have uploaded something first, or the GitHub sign-in failed."
}

Write-Host ""
Write-Host "DONE! Open the repo page and refresh:" -ForegroundColor Green
Write-Host "https://github.com/sabrimohammed292006-lab/AI-IT-Incident-Response-Agent"
