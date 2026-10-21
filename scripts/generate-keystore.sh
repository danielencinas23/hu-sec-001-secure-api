#!/usr/bin/env bash
# Genera el keystore PKCS12 autofirmado para el entorno local/desarrollo y exporta el
# certificado público (certs/secure-api.crt) para que curl/Postman/Angular puedan confiar en él.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYSTORE="$ROOT/src/main/resources/keystore/secure-api.p12"
CERT="$ROOT/certs/secure-api.crt"
PASSWORD="${SSL_KEYSTORE_PASSWORD:-changeit}"
KEYTOOL="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"

mkdir -p "$(dirname "$KEYSTORE")" "$(dirname "$CERT")"
rm -f "$KEYSTORE" "$CERT"

"$KEYTOOL" -genkeypair \
  -alias secure-api \
  -keyalg RSA -keysize 3072 -sigalg SHA256withRSA \
  -validity 825 \
  -storetype PKCS12 \
  -keystore "$KEYSTORE" \
  -storepass "$PASSWORD" \
  -dname "CN=localhost, OU=Backend, O=DWI, L=Local, C=ES" \
  -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" \
  -ext "KU=digitalSignature,keyEncipherment" \
  -ext "EKU=serverAuth"

"$KEYTOOL" -exportcert -rfc \
  -alias secure-api \
  -keystore "$KEYSTORE" \
  -storepass "$PASSWORD" \
  -file "$CERT"

echo "Keystore:    $KEYSTORE"
echo "Certificado: $CERT"
