package com.dwi.secureapi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;

/**
 * Arranca el servidor real (Tomcat + TLS) en un puerto aleatorio y verifica el canal cifrado a
 * nivel de socket: TLS 1.2/1.3 se negocian, versiones antiguas y tráfico en claro se rechazan.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, properties = "app.server.http-port=-1")
@ExtendWith(OutputCaptureExtension.class)
class TlsHandshakeIntegrationTest {

    static SSLContext trustingSslContext;

    @LocalServerPort
    int port;

    /** Confía únicamente en el certificado autofirmado del keystore de desarrollo. */
    @BeforeAll
    static void loadTrustStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (InputStream in = new ClassPathResource("keystore/secure-api.p12").getInputStream()) {
            keystore.load(in, "changeit".toCharArray());
        }
        Certificate cert = keystore.getCertificate("secure-api");

        KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        truststore.load(null, null);
        truststore.setCertificateEntry("secure-api", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(truststore);

        trustingSslContext = SSLContext.getInstance("TLS");
        trustingSslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
    }

    @ParameterizedTest
    @ValueSource(strings = { "TLSv1.2", "TLSv1.3" })
    void allowedProtocolsNegotiateSuccessfully(String protocol) throws Exception {
        try (SSLSocket socket = (SSLSocket) trustingSslContext.getSocketFactory().createSocket("localhost", port)) {
            socket.setEnabledProtocols(new String[] { protocol });
            socket.startHandshake();

            assertThat(socket.getSession().getProtocol()).isEqualTo(protocol);
            assertThat(socket.getSession().getCipherSuite()).containsAnyOf("GCM", "CHACHA20");
        }
    }

    @Test
    void clientThatDoesNotTrustCertificateFailsHandshake() throws Exception {
        SSLContext defaultContext = SSLContext.getInstance("TLS");
        defaultContext.init(null, null, null); // truststore por defecto del JDK: no conoce el autofirmado
        try (SSLSocket socket = (SSLSocket) defaultContext.getSocketFactory().createSocket("localhost", port)) {
            assertThatThrownBy(socket::startHandshake).isInstanceOf(SSLHandshakeException.class);
        }
    }

    /**
     * Envía a mano un ClientHello TLS 1.1 (el JDK cliente ya no permite generarlo) y comprueba que el
     * servidor responde con la alerta fatal {@code protocol_version} y que el fallo queda registrado
     * con el mensaje personalizado.
     */
    @Test
    void tls11ClientHelloIsRejectedWithProtocolVersionAlert(CapturedOutput output) throws Exception {
        try (Socket socket = new Socket("localhost", port)) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            out.write(tls11ClientHello());
            out.flush();

            DataInputStream in = new DataInputStream(socket.getInputStream());
            byte[] record = new byte[7];
            in.readFully(record);

            assertThat(record[0]).as("tipo de registro: alert").isEqualTo((byte) 0x15);
            assertThat(record[5]).as("nivel: fatal").isEqualTo((byte) 0x02);
            assertThat(record[6]).as("descripción: protocol_version").isEqualTo((byte) 70);
        }

        assertEventuallyLogged(output, "TLS_HANDSHAKE_FAILED");
        assertThat(output.getOut()).contains("el servidor solo acepta TLSv1.2 y TLSv1.3");
    }

    @Test
    void plainHttpOnHttpsPortIsRejected(CapturedOutput output) throws Exception {
        try (Socket socket = new Socket("localhost", port)) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(
                    "GET /api/public/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
            String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);

            assertThat(response).startsWith("HTTP/1.1 400").contains("requires TLS").doesNotContain("\"UP\"");
        }
        // Subcadena ASCII: la consola de Windows puede no usar UTF-8
        assertEventuallyLogged(output, "sin cifrar (HTTP) en el puerto HTTPS");
    }

    @Test
    void fullLoginFlowOverHttps() throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trustingSslContext).build();
        String base = "https://localhost:" + port;

        HttpResponse<String> unauthorized = client.send(
                HttpRequest.newBuilder(URI.create(base + "/api/users/me")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(unauthorized.statusCode()).isEqualTo(401);

        HttpResponse<String> login = client.send(
                HttpRequest.newBuilder(URI.create(base + "/api/auth/login"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"user\",\"password\":\"user123\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(login.statusCode()).isEqualTo(200);
        String token = JsonPath.read(login.body(), "$.access_token");

        HttpResponse<String> me = client.send(
                HttpRequest.newBuilder(URI.create(base + "/api/users/me"))
                        .header("Authorization", "Bearer " + token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(me.statusCode()).isEqualTo(200);
        assertThat(me.body()).contains("\"username\":\"user\"");

        HttpResponse<String> tlsInfo = client.send(
                HttpRequest.newBuilder(URI.create(base + "/api/public/tls-info")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(tlsInfo.body()).contains("\"secure\":true").containsPattern("TLSv1\\.[23]");
    }

    // ------------------------------------------------------------------ helpers

    private static void assertEventuallyLogged(CapturedOutput output, String text) throws InterruptedException {
        for (int i = 0; i < 50 && !output.getOut().contains(text); i++) {
            Thread.sleep(100);
        }
        assertThat(output.getOut()).contains(text);
    }

    /** ClientHello mínimo con versión 0x0302 (TLS 1.1) y suites CBC clásicas, sin extensiones. */
    private static byte[] tls11ClientHello() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(new byte[] { 0x03, 0x02 }); // client_version = TLS 1.1
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        body.writeBytes(random);
        body.write(0); // session_id vacío
        body.writeBytes(new byte[] { 0x00, 0x04, (byte) 0xC0, 0x13, 0x00, 0x2F }); // ECDHE_RSA_AES128_CBC_SHA, RSA_AES128_CBC_SHA
        body.writeBytes(new byte[] { 0x01, 0x00 }); // compresión: null
        byte[] hello = body.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        int handshakeLength = hello.length + 4;
        record.writeBytes(new byte[] { 0x16, 0x03, 0x01, (byte) (handshakeLength >> 8), (byte) handshakeLength });
        record.writeBytes(new byte[] { 0x01, 0x00, (byte) (hello.length >> 8), (byte) hello.length });
        record.writeBytes(hello);
        return record.toByteArray();
    }
}
