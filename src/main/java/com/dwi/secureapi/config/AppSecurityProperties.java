package com.dwi.secureapi.config;

import java.time.Duration;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.security")
public record AppSecurityProperties(
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull Cors cors,
        @Valid @NotEmpty List<DemoUser> users) {

    public record Jwt(
            @NotBlank @Size(min = 32, message = "el secreto JWT debe tener al menos 32 caracteres (HS256)") String secret,
            @NotBlank String issuer,
            @NotNull Duration expiration) {
    }

    public record Cors(@NotNull List<String> allowedOrigins) {
    }

    public record DemoUser(@NotBlank String username, @NotBlank String password, @NotEmpty List<String> roles) {
    }
}
