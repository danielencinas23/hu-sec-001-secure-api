# Genera el keystore PKCS12 autofirmado para el entorno local/desarrollo y exporta el
# certificado público (certs/secure-api.crt) para que curl/Postman/Angular puedan confiar en él.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$keystore = Join-Path $root 'src\main\resources\keystore\secure-api.p12'
$cert = Join-Path $root 'certs\secure-api.crt'
$password = if ($env:SSL_KEYSTORE_PASSWORD) { $env:SSL_KEYSTORE_PASSWORD } else { 'changeit' }
$keytool = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\keytool.exe' } else { 'keytool' }

New-Item -ItemType Directory -Force (Split-Path $keystore), (Split-Path $cert) | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $keystore, $cert

& $keytool -genkeypair `
    -alias secure-api `
    -keyalg RSA -keysize 3072 -sigalg SHA256withRSA `
    -validity 825 `
    -storetype PKCS12 `
    -keystore $keystore `
    -storepass $password `
    -dname 'CN=localhost, OU=Backend, O=DWI, L=Local, C=ES' `
    -ext 'SAN=dns:localhost,ip:127.0.0.1,ip:::1' `
    -ext 'KU=digitalSignature,keyEncipherment' `
    -ext 'EKU=serverAuth'
if ($LASTEXITCODE -ne 0) { throw 'keytool -genkeypair falló' }

& $keytool -exportcert -rfc -alias secure-api -keystore $keystore -storepass $password -file $cert
if ($LASTEXITCODE -ne 0) { throw 'keytool -exportcert falló' }

Write-Host "Keystore:    $keystore"
Write-Host "Certificado: $cert"
