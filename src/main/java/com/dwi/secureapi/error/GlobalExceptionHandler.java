package com.dwi.secureapi.error;

import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Traduce las excepciones lanzadas por los controladores (p. ej. el login) a respuestas
 * {@link ApiError}. Los 401/403 de la cadena de filtros los gestionan los manejadores de
 * {@code com.dwi.secureapi.security}.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiError> handleAuthentication(AuthenticationException ex, HttpServletRequest request) {
        // Mensaje genérico para no revelar si el usuario existe o no
        String code = "INVALID_CREDENTIALS";
        String message = "Usuario o contraseña incorrectos";
        if (ex instanceof LockedException) {
            code = "ACCOUNT_LOCKED";
            message = "La cuenta está bloqueada";
        } else if (ex instanceof DisabledException) {
            code = "ACCOUNT_DISABLED";
            message = "La cuenta está deshabilitada";
        } else if (!(ex instanceof BadCredentialsException)) {
            code = "AUTHENTICATION_FAILED";
            message = "No se pudo completar la autenticación";
        }
        return build(HttpStatus.UNAUTHORIZED, code, message, request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .sorted()
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message, request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "MALFORMED_REQUEST", "El cuerpo de la petición no es un JSON válido",
                request);
    }

    private static ResponseEntity<ApiError> build(HttpStatus status, String code, String message,
            HttpServletRequest request) {
        return ResponseEntity.status(status)
                .body(ApiError.of(status.value(), status.getReasonPhrase(), code, message, request.getRequestURI()));
    }
}
