# Capture the SOC console (newest incident's three-tier trace) as a PNG with headless Microsoft Edge.
# Uses a throwaway profile, so the user's own Edge profile and windows are never touched.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Url = "http://127.0.0.1:8000/?snapshot#latest",
    [int]$Width = 1440,
    [int]$Height = 1250,
    [int]$TimeoutSec = 45
)
$edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
$prof = Join-Path $env:TEMP "hrt_edge_snapshot_profile"
if (Test-Path $Out) { Remove-Item $Out -Force }
$edgeArgs = @("--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
              "--user-data-dir=`"$prof`"", "--window-size=$Width,$Height", "--virtual-time-budget=6000",
              "--screenshot=`"$Out`"", $Url)
$p = Start-Process -FilePath $edge -ArgumentList $edgeArgs -PassThru -WindowStyle Hidden
if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    Write-Output "timed out after $TimeoutSec s; stopping this capture's Edge processes"
}
# clean up only the processes that belong to this capture profile
Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
    Where-Object { $_.CommandLine -like "*hrt_edge_snapshot_profile*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if (Test-Path $Out) { Write-Output ("saved " + $Out + " (" + (Get-Item $Out).Length + " bytes)") }
else { Write-Output "no screenshot produced" }
