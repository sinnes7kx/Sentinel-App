# Runs as the desktop user. Only DISM and the signed Microsoft MSI need elevation.
$ErrorActionPreference = 'Stop'
$system = [Environment]::SystemDirectory
$wsl = Join-Path $system 'wsl.exe'
if ((Test-Path $wsl) -and (Get-Command $wsl)) {
    & $wsl --version *> $null
    if ($LASTEXITCODE -eq 0) {
        & $wsl --status *> $null
        if ($LASTEXITCODE -eq 0) { exit 0 }
    }
}
$msi = Join-Path $PSScriptRoot 'wsl-x64.msi'
$signature = Get-AuthenticodeSignature -LiteralPath $msi
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'Windows could not verify the Microsoft WSL installer signature.'
}
$dism = Start-Process (Join-Path $system 'dism.exe') -ArgumentList '/Online /Enable-Feature /FeatureName:VirtualMachinePlatform /All /NoRestart /LimitAccess' -Verb RunAs -Wait -PassThru
if ($dism.ExitCode -notin @(0,3010)) { throw "Windows could not enable Virtual Machine Platform (DISM $($dism.ExitCode))." }
$installer = Start-Process (Join-Path $system 'msiexec.exe') -ArgumentList "/i `"$msi`" /passive /norestart" -Verb RunAs -Wait -PassThru
if ($installer.ExitCode -notin @(0,1638,3010)) { throw "WSL installation returned $($installer.ExitCode)." }
if (($dism.ExitCode -eq 3010) -or ($installer.ExitCode -eq 3010)) {
    exit 3010
}
