param(
    [switch]$DryRun,
    [switch]$InstallMsys2Packages
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param([string[]]$Command)
    if ($DryRun) {
        Write-Host "[dry-run] $($Command -join ' ')"
    } else {
        & $Command[0] @($Command[1..($Command.Length - 1)])
    }
}

Write-Host "Installing DAH Toolset P0 host dependencies for Windows."

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "winget is not available. Install App Installer / Windows Package Manager first: https://learn.microsoft.com/windows/package-manager/winget/"
}

$wingetPackages = @(
    @("Kitware.CMake", "CMake"),
    @("Git.Git", "Git"),
    @("LLVM.LLVM", "LLVM"),
    @("Ninja-build.Ninja", "Ninja"),
    @("Python.Python.3.12", "Python"),
    @("MSYS2.MSYS2", "MSYS2")
)

foreach ($pkg in $wingetPackages) {
    Write-Host "winget install $($pkg[1])"
    Invoke-Step @("winget", "install", "--id", $pkg[0], "-e", "--accept-package-agreements", "--accept-source-agreements")
}

$msysBashCandidates = @(
    "C:\msys64\usr\bin\bash.exe",
    "$env:LOCALAPPDATA\Programs\msys64\usr\bin\bash.exe"
)
$msysBash = $msysBashCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($InstallMsys2Packages) {
    if (-not $msysBash) {
        throw "MSYS2 bash was not found. Install MSYS2 first, then re-run with -InstallMsys2Packages."
    }
    $pacman = "pacman -S --needed --noconfirm mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-clang mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-gdb mingw-w64-ucrt-x86_64-python mingw-w64-ucrt-x86_64-python-pytest make git"
    Invoke-Step @($msysBash, "-lc", $pacman)
} else {
    Write-Host "MSYS2 package install skipped. Re-run with -InstallMsys2Packages after MSYS2 is installed."
}

Write-Host "Windows limitations: Linux strace and AFL++ are best run via WSL2, Docker, or a Linux runner. Native Windows Toolset can still use CMake, Ninja, LLVM/clang, Git, Python, and MSYS2 GDB."

$check = Join-Path $PSScriptRoot "check_environment.py"
Invoke-Step @("python", $check, "--write-config")
