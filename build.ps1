param(
    [string]$OutputDir = "bin"
)

$ErrorActionPreference = "Stop"

$env:CGO_ENABLED = "0"

$targets = @(
    @{ Label = "windows legacy (Server 2008 R2+)"; GoCmd = "go1.20.14"; OS = "windows"; Arch = "amd64"; Dir = "legacy-amd64"; Ext = ".exe" },
    @{ Label = "windows amd64";                   GoCmd = "go";         OS = "windows"; Arch = "amd64"; Dir = "windows-amd64"; Ext = ".exe" },
    @{ Label = "windows arm64";                    GoCmd = "go";         OS = "windows"; Arch = "arm64"; Dir = "windows-arm64"; Ext = ".exe" },
    @{ Label = "linux amd64";                     GoCmd = "go";         OS = "linux";   Arch = "amd64"; Dir = "linux-amd64";   Ext = "" },
    @{ Label = "linux arm64";                     GoCmd = "go";         OS = "linux";   Arch = "arm64"; Dir = "linux-arm64";   Ext = "" },
    @{ Label = "darwin amd64";                    GoCmd = "go";         OS = "darwin";  Arch = "amd64"; Dir = "darwin-amd64";  Ext = "" },
    @{ Label = "darwin arm64";                     GoCmd = "go";         OS = "darwin";  Arch = "arm64"; Dir = "darwin-arm64";  Ext = "" }
)

$modules = @(
    "isolation", "shell", "collect", "kill", "quarantine", "sysinfo", "user-mgmt",
    "dns", "firewall", "yara", "hash", "persistence", "netconfig", "log-collect", "integrity"
)

foreach ($target in $targets) {
    $env:GOOS = $target.OS
    $env:GOARCH = $target.Arch
    $dir = "$OutputDir/$($target.Dir)"
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

    Write-Host "`n[$($target.Label)] -> $dir/" -ForegroundColor Cyan

    foreach ($mod in $modules) {
        $outFile = "$dir/$mod$($target.Ext)"
        Write-Host "  $outFile"
        & $target.GoCmd build -ldflags="-s -w" -o $outFile "./cmd/$mod"
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $mod ($($target.Label))" }
    }
}

Write-Host "`nDone." -ForegroundColor Green
Get-ChildItem $OutputDir -Recurse -File | Format-Table @{L="Path";E={$_.FullName.Replace((Resolve-Path $OutputDir).Path + "\","")}}, Length -AutoSize
