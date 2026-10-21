package com.dwi.secureapi.security;

import java.io.IOException;

import com.dwi.secureapi.error.ApiErrorWriter;
import com.dwi.secureapi.logging.SecurityAudit;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * Responde 401 Unauthorized con cuerpo JSON cuando la petición no trae credenciales o el token
 * Bearer es inválido/expirado. Añade la cabecera {@code WWW-Authenticate} según RFC 6750.
 */
@Component
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ApiErrorWriter errorWriter;

    public JsonAuthenticationEntryPoint(ApiErrorWriter errorWriter) {
        this.errorWriter = errorWriter;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        boolean invalidToken = authException instanceof InvalidBearerTokenException;
        String code = invalidToken ? "TOKEN_INVALID" : "AUTHENTICATION_REQUIRED";
        String message = invalidToken
                ? "El token de acceso es inválido o ha expirado"
                : "Se requiere un token Bearer válido para acceder a este recurso";

        SecurityAudit.LOG.warn("401 {} {} {} desde {} - {}", code, request.getMethod(), request.getRequestURI(),
                request.getRemoteAddr(), authException.getMessage());

        // Las cabeceras HTTP deben ser ASCII: la descripción en español va solo en el cuerpo JSON
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, invalidToken
                ? "Bearer error=\"invalid_token\", error_description=\"The access token is invalid or expired\""
                : "Bearer");
        errorWriter.write(response, HttpStatus.UNAUTHORIZED, code, message, request.getRequestURI());
    }
}
