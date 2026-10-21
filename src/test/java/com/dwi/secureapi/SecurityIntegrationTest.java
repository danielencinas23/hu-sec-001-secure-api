package com.dwi.secureapi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItems;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Verifica las reglas de la SecurityFilterChain: 200 con token válido, 401 sin token o con token
 * inválido, 403 sin el rol requerido, y que las peticiones sin cifrar se redirigen o rechazan.
 */
@SpringBootTest(properties = "app.server.http-port=-1")
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    JwtEncoder jwtEncoder;

    // ------------------------------------------------------------------ login

    @Test
    void loginWithValidCredentialsReturnsBearerToken() throws Exception {
        mvc.perform(https(post("/api/auth/login"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"admin123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(1800))
                .andExpect(jsonPath("$.roles", hasItems("USER", "ADMIN")))
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void loginWithWrongPasswordReturns401() throws Exception {
        mvc.perform(https(post("/api/auth/login"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void loginWithMissingFieldsReturns400() throws Exception {
        mvc.perform(https(post("/api/auth/login"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    // ------------------------------------------------------------------ 401 / 403 / 200

    @Test
    void publicEndpointDoesNotRequireToken() throws Exception {
        mvc.perform(https(get("/api/public/health")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(header().string("Strict-Transport-Security", containsString("max-age=31536000")));
    }

    @Test
    void protectedEndpointWithoutTokenReturns401() throws Exception {
        mvc.perform(https(get("/api/users/me")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"))
                .andExpect(jsonPath("$.path").value("/api/users/me"));
    }

    @Test
    void protectedEndpointWithTamperedTokenReturns401() throws Exception {
        String token = login("user", "user123");
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        mvc.perform(https(get("/api/users/me")).header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")))
                .andExpect(jsonPath("$.code").value("TOKEN_INVALID"));
    }

    @Test
    void protectedEndpointWithExpiredTokenReturns401() throws Exception {
        Instant past = Instant.now().minusSeconds(3600);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("secure-api").subject("user").issuedAt(past.minusSeconds(60)).expiresAt(past)
                .claim("roles", List.of("USER")).build();
        String expired = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
                claims)).getTokenValue();

        mvc.perform(https(get("/api/users/me")).header(HttpHeaders.AUTHORIZATION, "Bearer " + expired))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_INVALID"));
    }

    @Test
    void protectedEndpointWithValidTokenReturns200() throws Exception {
        String token = login("user", "user123");
        mvc.perform(https(get("/api/users/me")).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user"))
                .andExpect(jsonPath("$.roles", hasItems("USER")));
    }

    @Test
    void adminEndpointWithUserRoleReturns403() throws Exception {
        String token = login("user", "user123");
        mvc.perform(https(get("/api/admin/stats")).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"))
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void adminEndpointWithAdminRoleReturns200() throws Exception {
        String token = login("admin", "admin123");
        mvc.perform(https(get("/api/admin/stats")).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.availableProcessors").isNumber());
    }

    // ------------------------------------------------------------------ CORS

    @Test
    void corsPreflightFromAngularOriginIsAllowed() throws Exception {
        mvc.perform(https(options("/api/users/me"))
                        .header(HttpHeaders.ORIGIN, "https://localhost:4200")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://localhost:4200"));
    }

    @Test
    void corsPreflightFromUnknownOriginIsRejected() throws Exception {
        mvc.perform(https(options("/api/users/me"))
                        .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isForbidden());
    }

    // ------------------------------------------------------------------ HTTP sin cifrar

    @Test
    void plainHttpGetIsRedirectedToHttps() throws Exception {
        mvc.perform(get("http://localhost:8080/api/users/me?x=1"))
                .andExpect(status().isMovedPermanently())
                .andExpect(header().string(HttpHeaders.LOCATION, "https://localhost:8443/api/users/me?x=1"));
    }

    @Test
    void plainHttpPostIsRejected() throws Exception {
        mvc.perform(post("http://localhost:8080/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"admin123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("HTTPS_REQUIRED"));
    }

    // ------------------------------------------------------------------ helpers

    private String login(String username, String password) throws Exception {
        String body = mvc.perform(https(post("/api/auth/login"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String token = JsonPath.read(body, "$.access_token");
        assertThat(token).isNotBlank();
        return token;
    }

    /** Simula una petición recibida por el conector HTTPS. */
    private static MockHttpServletRequestBuilder https(MockHttpServletRequestBuilder builder) {
        return builder.secure(true);
    }
}
