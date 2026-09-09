$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -LiteralPath $ProjectDir

function Find-Python {
    $candidates = @("py", "python", "python3")
    foreach ($candidate in $candidates) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "Python 3 was not found. Install it from https://www.python.org/downloads/ and retry."
}

$Python = Find-Python
& $Python -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10 or newer is required'"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.10 or newer is required."
}

& $Python -m pip --version
if ($LASTEXITCODE -ne 0) {
    throw "pip is unavailable. Reinstall Python with the 'pip' option enabled."
}

$VenvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    & $Python -m venv ".venv"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create the .venv virtual environment."
    }
}

& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "pip upgrade failed."
}
& $VenvPython -m pip install --requirement "requirements.txt"
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "Run a scan:"
Write-Host ".\.venv\Scripts\python.exe cyberrecon.py --target example.com --quick"
Write-Host "No API key or external AI service is required."
Write-Host "Only scan systems you own or are explicitly authorized to assess."
