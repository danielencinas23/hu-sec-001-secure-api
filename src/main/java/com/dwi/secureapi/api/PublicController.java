package com.dwi.secureapi.api;

import java.time.Instant;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints públicos (sin token), útiles para comprobar el canal TLS negociado. */
@RestController
@RequestMapping("/api/public")
public class PublicController {

    /** Atributos de petición que Tomcat expone para conexiones TLS. */
    private static final String PROTOCOL_ATTR = "org.apache.tomcat.util.net.secure_protocol_version";
    private static final String CIPHER_ATTR = "jakarta.servlet.request.cipher_suite";

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "UP", "timestamp", Instant.now());
    }

    /** Devuelve el protocolo y la suite de cifrado con los que el cliente se ha conectado. */
    @GetMapping("/tls-info")
    public Map<String, Object> tlsInfo(HttpServletRequest request) {
        Object protocol = request.getAttribute(PROTOCOL_ATTR);
        Object cipher = request.getAttribute(CIPHER_ATTR);
        return Map.of(
                "secure", request.isSecure(),
                "scheme", request.getScheme(),
                "protocol", protocol != null ? protocol : "desconocido",
                "cipherSuite", cipher != null ? cipher : "desconocido");
    }
}
