package com.dwi.secureapi.error;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Cuerpo JSON uniforme para todas las respuestas de error del API.
 *
 * @param code identificador estable y legible por máquinas (p. ej. {@code TOKEN_INVALID})
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(Instant timestamp, int status, String error, String code, String message, String path) {

    public static ApiError of(int status, String error, String code, String message, String path) {
        return new ApiError(Instant.now(), status, error, code, message, path);
    }
}
