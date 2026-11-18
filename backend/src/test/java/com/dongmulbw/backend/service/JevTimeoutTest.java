
package com.dongmulbw.backend.service;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class JevTimeoutTest {

    @Test
    void testSlowJevResponse() throws Exception {

        HttpServer mockServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0),
                0
        );

        mockServer.createContext("/detect", exchange -> {
            try {
                // Jev 서버가 3초 동안 응답하지 않는 상황
                Thread.sleep(3000);

                String json = """
                        {
                          "status": "SUCCESS",
                          "jevAnalysis": {
                            "risk_level": "safe",
                            "confidence": 0.90
                          }
                        }
                        """;

                byte[] bytes =
                        json.getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().set(
                        "Content-Type",
                        "application/json"
                );

                exchange.sendResponseHeaders(200, bytes.length);

                try (var output = exchange.getResponseBody()) {
                    output.write(bytes);
                }

            } catch (Exception e) {
                exchange.close();
            }
        });

        mockServer.start();

        try {
            int port = mockServer.getAddress().getPort();

            JevAnalysisService service = new JevAnalysisService(
                    "http://127.0.0.1:" + port
            );

            long start = System.nanoTime();

            try {
                Map<String, Object> result =
                        service.analyze("https://example.com/");

                System.out.println(
                        "Jev 응답 결과: " + result
                );

            } catch (RuntimeException e) {
                System.out.println(
                        "Jev 요청 예외: "
                                + e.getClass().getSimpleName()
                );
            }

            long elapsed = TimeUnit.NANOSECONDS.toMillis(
                    System.nanoTime() - start
            );

            System.out.println(
                    "Jev 응답 소요 시간: " + elapsed + "ms"
            );

            // 응답 지연 상황을 실제로 관찰했는지 확인
            assertTrue(elapsed >= 2000,
                    "예상보다 너무 빠르게 종료되었습니다.");

            System.out.println(
                    "Jev 응답 지연 테스트: PASS"
            );

        } finally {
            mockServer.stop(0);
        }
    }

@Test
void testJevReadTimeout() throws Exception {

    HttpServer mockServer = HttpServer.create(
            new InetSocketAddress("127.0.0.1", 0),
            0
    );

    mockServer.createContext("/detect", exchange -> {
        try {
            // 서버가 7초 동안 응답하지 않는 상황
            Thread.sleep(7000);

            byte[] bytes = """
                    {
                      "jevAnalysis": {
                        "risk_level": "safe",
                        "confidence": 0.9
                      }
                    }
                    """.getBytes(StandardCharsets.UTF_8);

            exchange.sendResponseHeaders(200, bytes.length);

            try (var output = exchange.getResponseBody()) {
                output.write(bytes);
            }

        } catch (Exception e) {
            exchange.close();
        }
    });

    mockServer.start();

    try {
        int port = mockServer.getAddress().getPort();

        JevAnalysisService service = new JevAnalysisService(
                "http://127.0.0.1:" + port
        );

        long start = System.nanoTime();

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> service.analyze("https://example.com/")
        );

        long elapsed = TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - start
        );

        System.out.println("Jev 타임아웃 발생 시간: " + elapsed + "ms");
        System.out.println("예외 메시지: " + exception.getMessage());

        assertNotNull(exception.getCause());

        // 5초 타임아웃을 중심으로 허용 범위 검증
        assertTrue(
                elapsed >= 4000 && elapsed < 7000,
                "예상 타임아웃 범위를 벗어났습니다: " + elapsed + "ms"
        );

        System.out.println("Jev 5초 타임아웃 테스트: PASS");

    } finally {
        mockServer.stop(0);
    }
}

}
