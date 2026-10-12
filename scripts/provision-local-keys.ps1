[CmdletBinding()]
param([string]$WorkspaceRoot = (Join-Path $PSScriptRoot '../..'))

$ErrorActionPreference = 'Stop'
$keyWorkspace = (Resolve-Path -LiteralPath $WorkspaceRoot).Path
$keyDirectory = Join-Path $keyWorkspace '.local/security'
[System.IO.Directory]::CreateDirectory($keyDirectory) | Out-Null
$privateFile = Join-Path $keyDirectory 'jwt-private.pem'
$publicFile = Join-Path $keyDirectory 'jwt-public.pem'

function Write-NewKeyFile([string]$Path, [string]$Content) {
    $keyStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $keyBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content + "`n")
        $keyStream.Write($keyBytes, 0, $keyBytes.Length)
    } finally { $keyStream.Dispose() }
}

# Never replace an existing signing key or generate a mismatched pair.
if ((Test-Path -LiteralPath $publicFile) -and !(Test-Path -LiteralPath $privateFile)) {
    throw 'Public key exists without its private key. Restore the matching private key instead of replacing the pair.'
}
$localRsa = [System.Security.Cryptography.RSA]::Create(3072)
try {
    if (Test-Path -LiteralPath $privateFile) {
        $localRsa.ImportFromPem([System.IO.File]::ReadAllText($privateFile))
    } else {
        Write-NewKeyFile $privateFile ($localRsa.ExportPkcs8PrivateKeyPem())
    }
    if (Test-Path -LiteralPath $publicFile) {
        $existingPublic = [System.Security.Cryptography.RSA]::Create()
        try {
            $existingPublic.ImportFromPem([System.IO.File]::ReadAllText($publicFile))
            if ($existingPublic.ExportSubjectPublicKeyInfoPem() -ne $localRsa.ExportSubjectPublicKeyInfoPem()) { throw 'Existing RSA public and private keys do not match.' }
        } finally { $existingPublic.Dispose() }
    } else {
        Write-NewKeyFile $publicFile ($localRsa.ExportSubjectPublicKeyInfoPem())
    }
} finally { $localRsa.Dispose() }

foreach ($localSecretName in @('internal.key', 'session-encryption.key')) {
    $localSecretPath = Join-Path $keyDirectory $localSecretName
    if (!(Test-Path -LiteralPath $localSecretPath)) {
        Write-NewKeyFile $localSecretPath ([Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)))
    } else {
        $existingSecret = [Convert]::FromBase64String([System.IO.File]::ReadAllText($localSecretPath).Trim())
        if ($existingSecret.Length -ne 32) { throw "Existing $localSecretName must contain a 32-byte Base64 key. It was not replaced." }
    }
}
Write-Output "Local security keys are ready in $keyDirectory. Existing keys were preserved; no key contents were printed."
