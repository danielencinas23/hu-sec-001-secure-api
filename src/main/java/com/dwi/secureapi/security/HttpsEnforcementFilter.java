package com.dwi.secureapi.security;

import java.io.IOException;
import java.util.Set;

import com.dwi.secureapi.error.ApiErrorWriter;
import com.dwi.secureapi.logging.SecurityAudit;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Primer filtro de la cadena (antes que Spring Security). Ninguna petición sin cifrar llega al API:
 * <ul>
 *   <li>GET/HEAD se redirigen con 301 a la misma URL en HTTPS (útil para navegadores).</li>
 *   <li>El resto de métodos (POST, PUT, ...) se rechazan con 400 y un error JSON: su cuerpo, por
 *       ejemplo credenciales, ya viajó en claro y redirigirlo solo animaría al cliente a repetirlo.</li>
 * </ul>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class HttpsEnforcementFilter extends OncePerRequestFilter {

    private static final Set<String> REDIRECTABLE_METHODS = Set.of("GET", "HEAD");

    private final ApiErrorWriter errorWriter;
    private final int httpsPort;

    public HttpsEnforcementFilter(ApiErrorWriter errorWriter, @Value("${server.port:8443}") int httpsPort) {
        this.errorWriter = errorWriter;
        this.httpsPort = httpsPort;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.isSecure()) {
            chain.doFilter(request, response);
            return;
        }

        if (REDIRECTABLE_METHODS.contains(request.getMethod())) {
            // getRequestURI() y getQueryString() ya vienen codificados tal y como los envió el cliente
            String target = "https://" + request.getServerName() + (httpsPort == 443 ? "" : ":" + httpsPort)
                    + request.getRequestURI()
                    + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
            SecurityAudit.LOG.info("HTTP_REDIRECT {} {} desde {} -> {}", request.getMethod(),
                    request.getRequestURI(), request.getRemoteAddr(), target);
            response.setStatus(HttpStatus.MOVED_PERMANENTLY.value());
            response.setHeader(HttpHeaders.LOCATION, target);
            return;
        }

        SecurityAudit.LOG.warn("HTTP_REJECTED {} {} desde {}: petición no cifrada", request.getMethod(),
                request.getRequestURI(), request.getRemoteAddr());
        errorWriter.write(response, HttpStatus.BAD_REQUEST, "HTTPS_REQUIRED",
                "Este API solo acepta conexiones cifradas mediante TLS 1.2 o TLS 1.3. "
                        + "Repita la petición usando https://" + request.getServerName() + ":" + httpsPort
                        + request.getRequestURI(),
                request.getRequestURI());
    }
}
