package com.dwi.secureapi.security;

import java.io.IOException;

import com.dwi.secureapi.error.ApiErrorWriter;
import com.dwi.secureapi.logging.SecurityAudit;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * Responde 403 Forbidden con cuerpo JSON cuando el usuario está autenticado pero no tiene el rol
 * exigido por el endpoint.
 */
@Component
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    private final ApiErrorWriter errorWriter;

    public JsonAccessDeniedHandler(ApiErrorWriter errorWriter) {
        this.errorWriter = errorWriter;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String user = auth != null ? auth.getName() : "anónimo";

        SecurityAudit.LOG.warn("403 ACCESS_DENIED usuario={} autoridades={} {} {} desde {}", user,
                auth != null ? auth.getAuthorities() : "[]", request.getMethod(), request.getRequestURI(),
                request.getRemoteAddr());

        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_scope\"");
        errorWriter.write(response, HttpStatus.FORBIDDEN, "ACCESS_DENIED",
                "No tiene permisos suficientes para acceder a este recurso", request.getRequestURI());
    }
}
