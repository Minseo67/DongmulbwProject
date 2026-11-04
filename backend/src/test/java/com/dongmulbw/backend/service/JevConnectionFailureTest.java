
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import static org.junit.jupiter.api.Assertions.*;

class JevConnectionFailureTest {

    @Test
    void testJevServerConnectionFailure() throws IOException {

        // 사용 가능한 로컬 포트를 확보
        int unusedPort;

        try (ServerSocket socket = new ServerSocket(
                0, 0, InetAddress.getLoopbackAddress())) {
            unusedPort = socket.getLocalPort();
        }

        // 테스트용 Jev 서비스 생성
        JevAnalysisService service = new JevAnalysisService(
                "http://127.0.0.1:" + unusedPort
        );

        // 연결 실패 시 예외가 발생하는지 확인
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> service.analyze("https://example.com/")
        );

        assertNotNull(exception.getCause());

        System.out.println("Jev 서버 연결 실패 테스트: PASS");
    }
}
