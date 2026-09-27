# Render slides of a .pptx to PNG using the installed Microsoft PowerPoint (COM).
# Usage: pwsh render.ps1 -Deck <path.pptx> -Out <dir> [-From 1] [-To 99] [-Width 1600]
param(
    [Parameter(Mandatory = $true)][string]$Deck,
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$From = 1,
    [int]$To = 999,
    [int]$Width = 1600
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
# PowerPoint is single-instance: if the user already has it open, COM attaches to *their* instance.
# In that case close only our own read-only copy and never call Quit().
$wasRunning = [bool](Get-Process POWERPNT -ErrorAction SilentlyContinue)
$app = New-Object -ComObject PowerPoint.Application
$pres = $null
try {
    $pres = $app.Presentations.Open((Resolve-Path $Deck).Path, -1, 0, 0)   # read-only, no window
    $h = [int]($Width * $pres.PageSetup.SlideHeight / $pres.PageSetup.SlideWidth)
    $last = [Math]::Min($To, $pres.Slides.Count)
    for ($i = $From; $i -le $last; $i++) {
        $file = Join-Path $Out ("slide{0:D2}.png" -f $i)
        $pres.Slides.Item($i).Export($file, "PNG", $Width, $h)
        Write-Output $file
    }
}
finally {
    if ($pres) { $pres.Close() }
    if (-not $wasRunning) { $app.Quit() }
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($app) | Out-Null
}
