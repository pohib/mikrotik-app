$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$Log = Join-Path $Root 'startup.log'
try {
    Start-Transcript -Path $Log -Force | Out-Null
    Write-Host '[1/4] Searching for Python 3.10 or newer...'

    $PythonCommand = $null
    $PythonPrefix = @()
    $PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($PyLauncher) {
        & $PyLauncher.Source -3 -c 'import sys; print(sys.version); print(sys.executable)' 2>&1
        if ($LASTEXITCODE -eq 0) {
            $PythonCommand = $PyLauncher.Source
            $PythonPrefix = @('-3')
        }
    }

    if (-not $PythonCommand) {
        $Candidates = @()
        $PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($PythonCmd) { $Candidates += $PythonCmd.Source }
        $Candidates += (Join-Path $env:LocalAppData 'Programs/Python/Python314/python.exe')
        $Candidates += (Join-Path $env:LocalAppData 'Programs/Python/Python313/python.exe')
        $Candidates += (Join-Path $env:LocalAppData 'Programs/Python/Python312/python.exe')
        $Candidates += (Join-Path $env:LocalAppData 'Programs/Python/Python311/python.exe')
        $Candidates += (Join-Path $env:LocalAppData 'Programs/Python/Python310/python.exe')
        foreach ($Candidate in $Candidates) {
            if (-not (Test-Path $Candidate)) { continue }
            if ($Candidate -match '\\WindowsApps\\') { continue }
            & $Candidate -c 'import sys; print(sys.version); print(sys.executable); raise SystemExit(0 if sys.version_info >= (3,10) else 1)' 2>&1
            if ($LASTEXITCODE -eq 0) { $PythonCommand = $Candidate; break }
        }
    }

    if (-not $PythonCommand) { throw 'Python 3.10+ was not found. Install it from python.org and enable the Python Launcher or PATH.' }
    Write-Host "Using Python: $PythonCommand $($PythonPrefix -join ' ')"

    $VenvPython = Join-Path $Root '.venv/Scripts/python.exe'
    if (-not (Test-Path $VenvPython)) {
        Write-Host '[2/4] Creating virtual environment...'
        & $PythonCommand @PythonPrefix -m venv (Join-Path $Root '.venv')
        if ($LASTEXITCODE -ne 0) { throw "venv creation failed with exit code $LASTEXITCODE" }
    } else { Write-Host '[2/4] Existing virtual environment found.' }

    Write-Host '[3/4] Installing dependencies...'
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed with exit code $LASTEXITCODE" }
    & $VenvPython -m pip install -r (Join-Path $Root 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw "dependency installation failed with exit code $LASTEXITCODE" }

    Write-Host '[4/4] Checking imports...'
    & $VenvPython -c 'import PySide6, paramiko; print(PySide6.__version__); print(paramiko.__version__)'
    if ($LASTEXITCODE -ne 0) { throw "import check failed with exit code $LASTEXITCODE" }

    Write-Host 'Launching MikroTik VPN Manager...'
    & $VenvPython (Join-Path $Root 'app.py')
    if ($LASTEXITCODE -ne 0) { throw "application exited with code $LASTEXITCODE" }
    Write-Host 'Application closed normally.'
}
catch {
    Write-Host ''
    Write-Host '[ERROR]' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host 'See startup.log for details.'
    if (-not (Test-Path $Log)) { $_ | Out-String | Set-Content -Path $Log -Encoding UTF8 }
    exit 1
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
}
exit 0
