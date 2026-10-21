package com.dwi.secureapi.config;

import org.apache.catalina.connector.Connector;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Abre un conector HTTP plano adicional (por defecto 8080) cuyo único propósito es atender a los
 * clientes que llegan sin cifrar: {@link com.dwi.secureapi.security.HttpsEnforcementFilter} los
 * redirige a HTTPS o rechaza la petición. Ningún endpoint del API se sirve en claro.
 */
@Configuration
@ConditionalOnExpression("${app.server.http-port:-1} >= 0")
public class HttpConnectorConfig {

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpConnectorCustomizer(
            @Value("${app.server.http-port}") int httpPort, ServerProperties serverProperties) {
        return factory -> {
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setScheme("http");
            connector.setSecure(false);
            connector.setPort(httpPort);
            connector.setRedirectPort(serverProperties.getPort() != null ? serverProperties.getPort() : 8443);
            factory.addAdditionalTomcatConnectors(connector);
        };
    }
}
