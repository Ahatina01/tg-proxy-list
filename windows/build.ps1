param([switch]$Test,[switch]$Live)
$ErrorActionPreference='Stop'
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Force bin | Out-Null
    $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (!(Test-Path $compiler)) { $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
    $common=@('/nologo','/optimize+','/codepage:65001')
    & $compiler @common /target:winexe /platform:anycpu /out:bin\TG-Proxy.exe /win32manifest:app.manifest /win32icon:app.ico /resource:app.ico,app.ico /resource:proxies.txt,proxies.txt /reference:System.Windows.Forms.dll /reference:System.Drawing.dll Program.cs ProxyCore.cs MtProbe.cs TelegramLauncher.cs
    if ($LASTEXITCODE -ne 0) { throw 'EXE compilation failed' }
    if ($Test) {
        & $compiler @common /target:exe /out:bin\Tests.exe Tests.cs ProxyCore.cs MtProbe.cs TelegramLauncher.cs
        if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed' }
        if ($Live) { & .\bin\Tests.exe --live } else { & .\bin\Tests.exe }
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    }
} finally { Pop-Location }
