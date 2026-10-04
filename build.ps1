$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
Set-Location -LiteralPath $projectRoot
python -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
& "$projectRoot\.venv\Scripts\python.exe" -c "import tkinter; root = tkinter.Tk(); root.withdraw(); root.destroy()"
if ($LASTEXITCODE -ne 0) { throw 'A working Python Tcl/Tk installation is required to build the GUI' }
& "$projectRoot\.venv\Scripts\python.exe" -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
& "$projectRoot\.venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name StreamsAIO-Recovery --add-data 'remote;remote' main.py
if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath "$projectRoot\dist\StreamsAIO-Recovery.exe"
