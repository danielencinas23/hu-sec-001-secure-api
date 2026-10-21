package com.dwi.secureapi.api;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints protegidos: requieren cualquier usuario autenticado con un JWT válido. */
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        return Map.of(
                "username", jwt.getSubject(),
                "roles", roles != null ? roles : List.of(),
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt());
    }
}
