package com.dwi.secureapi.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TlsHandshakeFailureAppenderTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "SSLHandshakeException: Client requested protocol TLSv1.1 is not enabled or supported in server context | Versión de protocolo no permitida",
            "SSLHandshakeException: no cipher suites in common | No hay suites de cifrado en común",
            "SSLHandshakeException: Received fatal alert: certificate_unknown | rechazó el certificado",
            "SSLException: Unsupported or unrecognized SSL message | sin cifrar",
            "IOException: Found an plain text HTTP request on what should be an encrypted TLS connection | sin cifrar",
            "SSLHandshakeException: Remote host terminated the handshake | cerró la conexión",
            "SSLException: something else | no clasificado" })
    void translatesJsseErrorsToCustomMessages(String detail, String expected) {
        assertThat(TlsHandshakeFailureAppender.explain(detail)).contains(expected);
    }
}
