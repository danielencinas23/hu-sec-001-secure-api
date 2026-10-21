package com.dwi.secureapi.auth;

import java.time.Instant;
import java.util.List;

import com.dwi.secureapi.config.AppSecurityProperties;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/** Emite tokens JWT firmados con HS256 para un usuario ya autenticado. */
@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final AppSecurityProperties.Jwt jwtProperties;

    public TokenService(JwtEncoder jwtEncoder, AppSecurityProperties properties) {
        this.jwtEncoder = jwtEncoder;
        this.jwtProperties = properties.jwt();
    }

    public TokenResponse issue(Authentication authentication) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(jwtProperties.expiration());
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring("ROLE_".length()))
                .toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .subject(authentication.getName())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("roles", roles)
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenResponse(token, "Bearer", jwtProperties.expiration().toSeconds(), expiresAt, roles);
    }
}
