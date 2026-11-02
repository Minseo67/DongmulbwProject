
package com.dongmulbw.backend.service;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class JevAnalysisServiceTest {

    private HttpServer mockServer;
    private JevAnalysisService jevService;
    private AtomicReference<String> receivedBody;

    @BeforeEach
    void setUp() throws Exception {

        receivedBody = new AtomicReference<>();

        // 테스트용 가짜 HTTP 서버
        // 포트 0: 사용 가능한 포트를 자동 선택
        mockServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0),
                0
        );

        mockServer.createContext("/detect", exchange -> {

            // Spring Boot에서 보낸 요청 내용 저장
            String body = new String(
                    exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8
            );

            receivedBody.set(body);

            // 가짜 Jev 분석 결과
            String response = """
                    {
                      "status": "SUCCESS",
                      "jevAnalysis": {
                        "url": "https://example.com/",
                        "risk_level": "safe",
                        "confidence": 0.72,
                        "probabilities": {
                          "safe": 0.79,
                          "caution": 0.14,
                          "danger": 0.01,
                          "unknown": 0.06
                        },
                        "phishing_suspicion": 0.15,
                        "model": "jev-test",
                        "cached": false
                      }
                    }
                    """;

            byte[] responseBytes =
                    response.getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set(
                    "Content-Type",
                    "application/json"
            );

            exchange.sendResponseHeaders(
                    200,
                    responseBytes.length
            );

            try (var output = exchange.getResponseBody()) {
                output.write(responseBytes);
            }
        });

        mockServer.start();

        int port = mockServer.getAddress().getPort();

        // 실제 Jev API가 아닌 가짜 서버로 연결
        jevService = new JevAnalysisService(
                "http://127.0.0.1:" + port
        );
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.stop(0);
        }
    }

    @Test
    void testJevConnection() {

        String originalUrl = "https://example.com/";

        Map<String, Object> result =
                jevService.analyze(originalUrl);

        assertNotNull(result);
        assertEquals("safe", result.get("risk_level"));
        assertEquals("jev-test", result.get("model"));

        System.out.println("Jev HTTP 통신 테스트: PASS");
    }

    @Test
    void testOriginalUrlTransfer() {

        String originalUrl =
                "HTTPS://Example.COM/login?next=home";

        jevService.analyze(originalUrl);

        String requestBody = receivedBody.get();

        assertNotNull(requestBody);

        // 원본 URL이 변경되지 않고 전달되는지 확인
        assertTrue(requestBody.contains(originalUrl));

        System.out.println("원본 URL 전달 테스트: PASS");
    }

    @Test
    void testJevResultParsing() {

        Map<String, Object> result =
                jevService.analyze("https://example.com/");

        assertEquals(0.72,
                ((Number) result.get("confidence")).doubleValue(),
                0.0001);

        assertEquals(false, result.get("cached"));

        assertTrue(result.containsKey("probabilities"));

        System.out.println("Jev 분석 결과 파싱 테스트: PASS");
    }
}
