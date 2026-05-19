# Build script for the mp + xrayrunner binaries.
#
# Produces both Windows and Linux/amd64 binaries into the dist\ folder.
#
# Usage:
#   .\build.ps1                # build everything
#   .\build.ps1 -Bin mp        # build only mp (windows + linux)
#   .\build.ps1 -Os linux      # build everything for one OS only

[CmdletBinding()]
param(
    [string]$Bin = "all",
    [string]$Os  = "all"
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

# (binary name, package import path)
$targets = @(
    @{ Name = "mp"; Pkg = "./cmd/mp" }
)

# (GOOS, GOARCH, file extension)
$platforms = @(
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe" }
    @{ OS = "linux";   Arch = "amd64"; Ext = ""     }
)

foreach ($t in $targets) {
    if ($Bin -ne "all" -and $Bin -ne $t.Name) { continue }

    foreach ($p in $platforms) {
        if ($Os -ne "all" -and $Os -ne $p.OS) { continue }

        $out = Join-Path $dist ("{0}-{1}-{2}{3}" -f $t.Name, $p.OS, $p.Arch, $p.Ext)
        Write-Host ("-> building {0} for {1}/{2} -> {3}" -f $t.Name, $p.OS, $p.Arch, $out)

        $env:GOOS   = $p.OS
        $env:GOARCH = $p.Arch
        $env:CGO_ENABLED = "0"

        & go build -trimpath -ldflags "-s -w" -o $out $t.Pkg
        if ($LASTEXITCODE -ne 0) {
            Write-Error "go build failed for $($t.Name) $($p.OS)/$($p.Arch)"
            exit $LASTEXITCODE
        }
    }
}

Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
Write-Host "`ndone - artifacts in $dist"
Get-ChildItem $dist | Format-Table Name, Length, LastWriteTime
