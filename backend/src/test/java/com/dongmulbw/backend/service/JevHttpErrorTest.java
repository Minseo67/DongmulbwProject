
package com.dongmulbw.backend.service;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.web.client.RestClientResponseException;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class JevHttpErrorTest {

    @ParameterizedTest
    @ValueSource(ints = {400, 404, 429, 500, 502, 503})
    void testJevHttpError(int statusCode) throws Exception {

        HttpServer mockServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0),
                0
        );

        mockServer.createContext("/detect", exchange -> {
            try {
                byte[] body = """
                        {"detail":"Mock HTTP error"}
                        """.getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().set(
                        "Content-Type", "application/json"
                );

                exchange.sendResponseHeaders(statusCode, body.length);

                try (var output = exchange.getResponseBody()) {
                    output.write(body);
                }
            } finally {
                exchange.close();
            }
        });

        mockServer.start();

        try {
            int port = mockServer.getAddress().getPort();

            JevAnalysisService service = new JevAnalysisService(
                    "http://127.0.0.1:" + port
            );

            IllegalStateException exception = assertThrows(
                    IllegalStateException.class,
                    () -> service.analyze("https://example.com/")
            );

            assertEquals(
                    "Jev FastAPI 서버 통신 실패",
                    exception.getMessage()
            );

            assertInstanceOf(
                    RestClientResponseException.class,
                    exception.getCause()
            );

            RestClientResponseException cause =
                    (RestClientResponseException) exception.getCause();

            assertEquals(
                    statusCode,
                    cause.getStatusCode().value()
            );

            System.out.println(
                    "HTTP " + statusCode + " 오류 처리: PASS"
            );

        } finally {
            mockServer.stop(0);
        }
    }
}
