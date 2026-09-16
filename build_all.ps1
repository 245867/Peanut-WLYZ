# ============================================================
# Peanut_WLYZ 全量构建脚本
# 用法: .\build_all.ps1 [Release|Debug] [x64|x86]
# 默认: Release x64
# ============================================================
param(
    [ValidateSet("Release","Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("x64","x86")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# 自动定位 MSBuild
$msbuild = $null
$searchDirs = @(
    "D:\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin"
)
foreach ($d in $searchDirs) {
    $candidate = Join-Path $d "MSBuild.exe"
    if (Test-Path $candidate) { $msbuild = $candidate; break }
}
if (-not $msbuild) { throw "未找到 MSBuild.exe，请安装 VS2019/2022" }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Peanut_WLYZ Build Script" -ForegroundColor Cyan
Write-Host " Config: $Configuration | Platform: $Platform" -ForegroundColor Cyan
Write-Host " MSBuild: $msbuild" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$failed = @()
$passed = 0

function Build-Proj($name, $vcxproj, $extraProps = @{}) {
    Write-Host "`n--- [$name] ---" -ForegroundColor Yellow
    $props = "/p:Configuration=$Configuration", "/p:Platform=$Platform", "/t:Build", "/m", "/v:minimal"
    foreach ($k in $extraProps.Keys) { $props += "/p:$k=$($extraProps[$k])" }
    & $msbuild $vcxproj $props 2>&1 | ForEach-Object {
        if ($_ -match "error |错误|失败|error$") { Write-Host $_ -ForegroundColor Red }
        elseif ($_ -match "warning ") { Write-Host $_ -ForegroundColor DarkYellow }
        else { Write-Host $_ }
    }
    if ($LASTEXITCODE -eq 0) { Write-Host "  ✅ PASS" -ForegroundColor Green; $script:passed++ }
    else { Write-Host "  ❌ FAIL" -ForegroundColor Red; $script:failed += $name }
}

# ---- Stage 1: Plugin DLLs ----
Write-Host "`n[Stage 1] Building Plugins" -ForegroundColor Magenta
$plugins = @(
    @{n="echo_plugin";           p="examples\echo_plugin\echo_plugin.vcxproj"},
    @{n="scene_plugin";          p="examples\scene_plugin\scene_plugin.vcxproj"},
    @{n="abogus_plugin";         p="examples\abogus_plugin\abogus_plugin.vcxproj"},
    @{n="resume_live_plugin";    p="examples\resume_live_plugin\resume_live_plugin.vcxproj"},
    @{n="system_info_plugin";    p="examples\system_info_plugin\system_info_plugin.vcxproj"}
)
foreach ($pl in $plugins) {
    Build-Proj $pl.n (Join-Path $root $pl.p)
}

# ---- Stage 2: MockServer + Tests ----
Write-Host "`n[Stage 2] Building Tests & Tools" -ForegroundColor Magenta
$tools = @(
    @{n="PeanutMockServer";      p="src\PeanutMockServer\PeanutMockServer.vcxproj"},
    @{n="PeanutTest";             p="src\PeanutTest\PeanutTest.vcxproj"},
    @{n="PeanutIntegrationTest";  p="src\PeanutIntegrationTest\PeanutIntegrationTest.vcxproj"},
    @{n="PeanutSdkDemo";          p="src\PeanutSdkDemo\PeanutSdkDemo.vcxproj"}
)
foreach ($t in $tools) {
    Build-Proj $t.n (Join-Path $root $t.p)
}

# ---- Stage 3: Client Demos ----
Write-Host "`n[Stage 3] Building Client Demos" -ForegroundColor Magenta
for ($i = 1; $i -le 3; $i++) {
    $demo = "client_demo$i"
    Build-Proj $demo (Join-Path $root "$demo\$demo.vcxproj")
}

# ---- Stage 4: PeanutGUI ----
Write-Host "`n[Stage 4] Building PeanutGUI" -ForegroundColor Magenta
Build-Proj "PeanutGUI" (Join-Path $root "src\PeanutGUI\PeanutGUI.vcxproj")

# ---- Summary ----
$elapsed = $sw.Elapsed.TotalSeconds.ToString("F1")
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Build Complete | Passed: $passed | Failed: $($failed.Count) | Elapsed: ${elapsed}s" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
if ($failed.Count -gt 0) {
    Write-Host "Failed: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "ALL PASSED" -ForegroundColor Green
exit 0
