param(
    [string]$Version = "dev",
    [string]$BuildDate = (Get-Date -Format "yyyy-MM-dd")
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $projectRoot "build"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$ldflags = "-s -w -X main.version=$Version -X main.buildDate=$BuildDate"

$targets = @(
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe" },
    @{ OS = "linux"; Arch = "amd64"; Ext = "" },
    @{ OS = "darwin"; Arch = "amd64"; Ext = "" },
    @{ OS = "darwin"; Arch = "arm64"; Ext = "" }
)

foreach ($target in $targets) {
    $env:GOOS = $target.OS
    $env:GOARCH = $target.Arch
    $name = "gophkeeper-$($target.OS)-$($target.Arch)$($target.Ext)"
    go build -trimpath -ldflags $ldflags -o (Join-Path $outputDir $name) ./cmd/gophkeeper
    if ($LASTEXITCODE -ne 0) {
        throw "build failed for $($target.OS)/$($target.Arch)"
    }
}

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
