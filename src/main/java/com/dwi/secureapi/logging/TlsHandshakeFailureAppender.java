package com.dwi.secureapi.logging;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;

/**
 * Appender de Logback conectado al logger de Tomcat
 * {@code org.apache.tomcat.util.net.NioEndpoint.handshake}. Cuando un handshake TLS falla no
 * existe todavía un canal HTTP por el que responder, así que el error se traduce a un mensaje
 * personalizado y comprensible en el log de auditoría de seguridad (consola + fichero).
 */
public class TlsHandshakeFailureAppender extends AppenderBase<ILoggingEvent> {

    private static final Pattern CLIENT = Pattern.compile("\\[([^\\]]+)\\][^\\[]*\\[(\\d+)\\]");

    @Override
    protected void append(ILoggingEvent event) {
        if (event.getThrowableProxy() == null) {
            return;
        }
        String detail = rootDetail(event.getThrowableProxy());
        SecurityAudit.LOG.warn("TLS_HANDSHAKE_FAILED cliente={} motivo=\"{}\" detalle=\"{}\"",
                client(event.getFormattedMessage()), explain(detail), detail);
    }

    /** Traduce los mensajes internos de JSSE a una explicación accionable. */
    static String explain(String detail) {
        String d = detail.toLowerCase(Locale.ROOT);
        if (d.contains("protocol") && (d.contains("not enabled") || d.contains("not supported")
                || d.contains("protocol_version") || d.contains("no appropriate protocol"))) {
            return "Versión de protocolo no permitida: el servidor solo acepta TLSv1.2 y TLSv1.3";
        }
        if (d.contains("cipher suites in common") || d.contains("insufficient_security")) {
            return "No hay suites de cifrado en común: el cliente no ofrece ninguna suite AEAD/ECDHE permitida";
        }
        if (d.contains("certificate_unknown") || d.contains("unknown_ca") || d.contains("bad_certificate")
                || d.contains("certificate_expired")) {
            return "El cliente rechazó el certificado del servidor (no confía en la CA, autofirmado o expirado)";
        }
        if (d.contains("unrecognized ssl message") || d.contains("plaintext") || d.contains("plain text")) {
            return "Se recibió tráfico sin cifrar (HTTP) en el puerto HTTPS";
        }
        if (d.contains("terminated the handshake") || d.contains("eof") || d.contains("connection reset")
                || d.contains("broken pipe")) {
            return "El cliente cerró la conexión durante el handshake";
        }
        return "Error de negociación TLS no clasificado";
    }

    private static String client(String message) {
        Matcher m = CLIENT.matcher(message == null ? "" : message);
        return m.find() ? m.group(1) + ":" + m.group(2) : "desconocido";
    }

    private static String rootDetail(IThrowableProxy proxy) {
        IThrowableProxy current = proxy;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        String message = current.getMessage();
        String className = current.getClassName().substring(current.getClassName().lastIndexOf('.') + 1);
        return message == null ? className : className + ": " + message;
    }
}
