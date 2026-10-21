# HU-SEC-001 · Autenticación y cifrado TLS/SSL en el API Backend

API REST en **Java 21 + Spring Boot 3.5 + Spring Security 6.5** que solo se sirve sobre
**HTTPS (TLS 1.2 / TLS 1.3)** y protege sus endpoints con **tokens JWT (Bearer)**.

| Épica | Rol | Modalidad |
|---|---|---|
| Seguridad e Infraestructura Backend | Desarrollador Backend | Individual |

---

## Cómo ejecutarlo

Requisitos: JDK 21 y Maven 3.9+.

```bash
mvn spring-boot:run          # o: mvn package && java -jar target/secure-api-1.0.0.jar
```

| Puerto | Protocolo | Comportamiento |
|---|---|---|
| `8443` | HTTPS (TLS 1.2 / 1.3) | Sirve el API |
| `8080` | HTTP | `GET`/`HEAD` → **301** a HTTPS · resto de métodos → **400 `HTTPS_REQUIRED`** |

Usuarios de demostración (definidos en `application.yml`, contraseñas cifradas con BCrypt al arrancar):

| Usuario | Contraseña | Roles |
|---|---|---|
| `user` | `user123` | `USER` |
| `admin` | `admin123` | `USER`, `ADMIN` |

### Endpoints

| Método | Ruta | Acceso |
|---|---|---|
| `POST` | `/api/auth/login` | Público. Devuelve `access_token` (JWT HS256, 30 min) |
| `GET` | `/api/public/health` | Público |
| `GET` | `/api/public/tls-info` | Público. Muestra el protocolo y la suite TLS negociados |
| `GET` | `/api/users/me` | Requiere token válido |
| `GET` | `/api/admin/stats` | Requiere token con rol `ADMIN` (si no → 403) |

---

## Criterios de aceptación → implementación

### 1. Configuración SSL/TLS

| Criterio | Dónde |
|---|---|
| Keystore PKCS12 generado con `keytool` (RSA 3072, SAN `localhost`/`127.0.0.1`) | [`scripts/generate-keystore.ps1`](scripts/generate-keystore.ps1) / [`.sh`](scripts/generate-keystore.sh) → `src/main/resources/keystore/secure-api.p12` |
| `server.ssl.key-store`, `key-store-type`, `key-store-password`, `enabled-protocols=TLSv1.2,TLSv1.3` | [`application.yml`](src/main/resources/application.yml) |
| Solo suites AEAD con ECDHE (forward secrecy) | `server.ssl.ciphers` en `application.yml` |
| Peticiones HTTP sin cifrar redirigidas o rechazadas | [`HttpConnectorConfig`](src/main/java/com/dwi/secureapi/config/HttpConnectorConfig.java) + [`HttpsEnforcementFilter`](src/main/java/com/dwi/secureapi/security/HttpsEnforcementFilter.java) |
| HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) | `SecurityConfig` |

Regenerar el keystore (también exporta `certs/secure-api.crt` para clientes):

```powershell
./scripts/generate-keystore.ps1         # Windows
./scripts/generate-keystore.sh          # Linux / macOS / Git Bash
```

Comando equivalente:

```bash
keytool -genkeypair -alias secure-api -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 825 \
  -storetype PKCS12 -keystore src/main/resources/keystore/secure-api.p12 -storepass changeit \
  -dname "CN=localhost, OU=Backend, O=DWI, L=Local, C=ES" \
  -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" -ext "EKU=serverAuth"
```

> El keystore incluido es **solo para desarrollo local**. En otros entornos se inyecta con
> variables de entorno: `SSL_KEYSTORE=file:/ruta/cert.p12`, `SSL_KEYSTORE_PASSWORD=...`.

### 2. Autenticación y autorización con Spring Security

[`SecurityConfig`](src/main/java/com/dwi/secureapi/config/SecurityConfig.java) define el bean `SecurityFilterChain`:

```java
.authorizeHttpRequests(auth -> auth
        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        .requestMatchers("/api/auth/**").permitAll()
        .requestMatchers("/api/public/**").permitAll()
        .requestMatchers("/error").permitAll()
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated())
.oauth2ResourceServer(oauth2 -> oauth2.jwt(...))
```

- **Stateless**: sin sesión ni cookies; CSRF deshabilitado porque la autenticación va en la cabecera `Authorization`.
- **JWT**: emitido por [`TokenService`](src/main/java/com/dwi/secureapi/auth/TokenService.java) y validado por `NimbusJwtDecoder` (firma HS256, `exp`, `nbf` e `iss`). El claim `roles` se convierte en autoridades `ROLE_*`.
- **CORS** para Angular: orígenes permitidos `https://localhost:4200` y `http://localhost:4200` (configurables con `CORS_ALLOWED_ORIGINS`).
- **401 / 403 en JSON**: [`JsonAuthenticationEntryPoint`](src/main/java/com/dwi/secureapi/security/JsonAuthenticationEntryPoint.java) y [`JsonAccessDeniedHandler`](src/main/java/com/dwi/secureapi/security/JsonAccessDeniedHandler.java).

| Situación | Estado | `code` |
|---|---|---|
| Sin cabecera `Authorization` | 401 | `AUTHENTICATION_REQUIRED` |
| Token manipulado, expirado o de otro emisor | 401 | `TOKEN_INVALID` |
| Usuario/contraseña incorrectos en el login | 401 | `INVALID_CREDENTIALS` |
| Token válido sin el rol requerido | 403 | `ACCESS_DENIED` |
| Petición no cifrada (POST/PUT/...) en el puerto 8080 | 400 | `HTTPS_REQUIRED` |
| Cuerpo de login inválido | 400 | `VALIDATION_ERROR` |

Ejemplo de respuesta:

```json
{
  "timestamp": "2026-10-21T01:18:35.347Z",
  "status": 403,
  "error": "Forbidden",
  "code": "ACCESS_DENIED",
  "message": "No tiene permisos suficientes para acceder a este recurso",
  "path": "/api/admin/stats"
}
```

### 3. Manejo de errores y registro de eventos de seguridad

Todos los eventos se escriben en el logger `SECURITY_AUDIT` (consola + `logs/security-audit.log`, rotado a diario o cada 10 MB).

**Errores de handshake TLS.** Cuando el handshake falla todavía no existe un canal HTTP por el que responder. Por eso [`TlsHandshakeFailureAppender`](src/main/java/com/dwi/secureapi/logging/TlsHandshakeFailureAppender.java) se engancha al logger interno de Tomcat `org.apache.tomcat.util.net.NioEndpoint.handshake` (configurado en [`logback-spring.xml`](src/main/resources/logback-spring.xml)) y traduce el error JSSE a un mensaje personalizado:

```
TLS_HANDSHAKE_FAILED cliente=127.0.0.1:14272 motivo="Versión de protocolo no permitida: el servidor solo acepta TLSv1.2 y TLSv1.3" detalle="SSLHandshakeException: (protocol_version) Client requested protocol TLSv1.1 is not enabled or supported in server context"
TLS_HANDSHAKE_FAILED cliente=127.0.0.1:14274 motivo="El cliente rechazó el certificado del servidor (no confía en la CA, autofirmado o expirado)" ...
TLS_HANDSHAKE_FAILED cliente=127.0.0.1:14275 motivo="Se recibió tráfico sin cifrar (HTTP) en el puerto HTTPS" ...
```

El cliente recibe la alerta TLS estándar correspondiente (`protocol_version`, `handshake_failure`...). Si envía HTTP plano al puerto 8443, Tomcat responde `400 This combination of host and port requires TLS.`

**Errores de autenticación**:

```
LOGIN_SUCCESS usuario=user autoridades=[ROLE_USER]
LOGIN_FAILURE usuario=admin motivo=BadCredentialsException
401 TOKEN_INVALID GET /api/users/me desde 127.0.0.1 - ... Jwt expired at 2026-10-21T00:17:25Z
403 ACCESS_DENIED usuario=user autoridades=[ROLE_USER] GET /api/admin/stats desde 127.0.0.1
HTTP_REDIRECT GET /api/users/me desde 127.0.0.1 -> https://localhost:8443/api/users/me
HTTP_REJECTED POST /api/auth/login desde 127.0.0.1: petición no cifrada
```

---

## Verificación del handshake con curl

`certs/secure-api.crt` es el certificado público autofirmado. Pasándolo con `--cacert`, curl valida la cadena sin usar `-k`.

```bash
# Handshake TLS 1.3 (por defecto) y detalle de la negociación
curl -v --cacert certs/secure-api.crt https://localhost:8443/api/public/tls-info
# {"scheme":"https","protocol":"TLSv1.3","secure":true,"cipherSuite":"TLS_AES_256_GCM_SHA384"}

# Forzar TLS 1.2
curl --cacert certs/secure-api.crt --tlsv1.2 --tls-max 1.2 https://localhost:8443/api/public/tls-info
# {"protocol":"TLSv1.2","cipherSuite":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", ...}

# TLS 1.1 → rechazado (curl: (35) error de handshake)
curl --cacert certs/secure-api.crt --tlsv1.1 --tls-max 1.1 https://localhost:8443/api/public/health

# HTTP → 301 a HTTPS (GET) o 400 HTTPS_REQUIRED (POST)
curl -i http://localhost:8080/api/users/me
curl -X POST http://localhost:8080/api/auth/login -H "Content-Type: application/json" -d '{"username":"user","password":"user123"}'

# Flujo de autenticación
curl --cacert certs/secure-api.crt https://localhost:8443/api/users/me                       # 401
TOKEN=$(curl -s --cacert certs/secure-api.crt -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" -d '{"username":"user","password":"user123"}' | jq -r .access_token)
curl --cacert certs/secure-api.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/users/me     # 200
curl --cacert certs/secure-api.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/admin/stats  # 403
```

Con OpenSSL también se puede inspeccionar el handshake:

```bash
openssl s_client -connect localhost:8443 -tls1_3 -CAfile certs/secure-api.crt </dev/null
openssl s_client -connect localhost:8443 -tls1_1 </dev/null   # alerta protocol_version
```

**Postman**: importar [`postman/secure-api.postman_collection.json`](postman/secure-api.postman_collection.json) y añadir `certs/secure-api.crt` en *Settings → Certificates → CA Certificates*.

**Angular**: el `ng serve` debe apuntar a `https://localhost:8443`. El navegador debe confiar en `certs/secure-api.crt`; para ello se importa en el almacén de certificados del sistema como CA raíz de confianza.

---

## Pruebas automatizadas

```bash
mvn test
```

27 pruebas:

- [`SecurityIntegrationTest`](src/test/java/com/dwi/secureapi/SecurityIntegrationTest.java) (MockMvc): login válido e inválido, validación, 401 sin token o con token manipulado/expirado, 403 por rol, 200 con token, CORS de Angular permitido y origen desconocido rechazado, redirección y rechazo de HTTP.
- [`TlsHandshakeIntegrationTest`](src/test/java/com/dwi/secureapi/TlsHandshakeIntegrationTest.java) (servidor Tomcat real en puerto aleatorio):
  - se negocian TLS 1.2 y TLS 1.3 con suites GCM/ChaCha20;
  - un cliente que no confía en el certificado falla;
  - un **ClientHello TLS 1.1 construido byte a byte** recibe la alerta fatal `protocol_version` y deja registrado `TLS_HANDSHAKE_FAILED`;
  - HTTP plano en el puerto 8443 se rechaza;
  - flujo completo login → `/me` sobre HTTPS.
- [`TlsHandshakeFailureAppenderTest`](src/test/java/com/dwi/secureapi/logging/TlsHandshakeFailureAppenderTest.java): traducción de los errores JSSE a mensajes personalizados.

---

## Variables de entorno

| Variable | Por defecto | Uso |
|---|---|---|
| `HTTPS_PORT` | `8443` | Puerto HTTPS |
| `HTTP_PORT` | `8080` | Puerto HTTP de redirección/rechazo (`-1` lo desactiva) |
| `SSL_KEYSTORE` | `classpath:keystore/secure-api.p12` | Keystore PKCS12 |
| `SSL_KEYSTORE_PASSWORD` | `changeit` | Contraseña del keystore |
| `JWT_SECRET` | secreto de desarrollo | Secreto HMAC (≥ 32 caracteres). **Obligatorio cambiarlo fuera de local** |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:4200,http://localhost:4200` | Orígenes del frontend |
| `DEMO_USER_PASSWORD` / `DEMO_ADMIN_PASSWORD` | `user123` / `admin123` | Contraseñas de los usuarios de demo |

## Estructura

```
src/main/java/com/dwi/secureapi
├── SecureApiApplication.java
├── api/        PublicController, UserController, AdminController
├── auth/       AuthController (login), TokenService (emisión JWT), DTOs
├── config/     SecurityConfig (SecurityFilterChain, CORS, JWT), HttpConnectorConfig, AppSecurityProperties
├── error/      ApiError, ApiErrorWriter, GlobalExceptionHandler
├── logging/    SecurityAudit, TlsHandshakeFailureAppender
└── security/   JsonAuthenticationEntryPoint (401), JsonAccessDeniedHandler (403),
                HttpsEnforcementFilter, SecurityEventListener
```
