
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.service.JevAnalysisService;
import com.dongmulbw.backend.service.UrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.DomainReputationService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class UrlAnalysisControllerJevTest {

    private UrlNormalizationService normalizationService;
    private UrlAnalysisService analysisService;
    private JevAnalysisService jevAnalysisService;
    private UrlAnalysisController controller;

    private static final String RAW_URL =
            "HTTPS://Example.COM/login?next=home";

    private static final String NORMALIZED_URL =
            "https://example.com/login?next=home";

    @BeforeEach
    void setUp() {
        normalizationService = mock(UrlNormalizationService.class);
        analysisService = mock(UrlAnalysisService.class);
        jevAnalysisService = mock(JevAnalysisService.class);

        controller = new UrlAnalysisController(
                normalizationService,
                analysisService,
                jevAnalysisService
        );

        UrlNormalizationResult normalized =
                new UrlNormalizationResult(
                        RAW_URL,
                        NORMALIZED_URL,
                        "https",
                        "example.com",
                        "test-hash",
                        "norm-v1"
                );

        when(normalizationService.normalize(RAW_URL))
                .thenReturn(normalized);

        UrlAnalysisService.AnalysisResult existingResult =
                new UrlAnalysisService.AnalysisResult(
                        null,
                        DomainReputationService.ReputationStatus.UNKNOWN,
                        false
                );

        when(analysisService.analyze(
                RAW_URL,
                NORMALIZED_URL,
                "example.com"
        )).thenReturn(existingResult);
    }

    @Test
    void testJevResultIncluded() {
        Map<String, Object> fakeJevResult = Map.of(
                "risk_level", "safe",
                "confidence", 0.72,
                "model", "jev-test",
                "cached", false
        );

        when(jevAnalysisService.analyze(RAW_URL))
                .thenReturn(fakeJevResult);

        ResponseEntity<?> response =
                controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        assertEquals(200, response.getStatusCode().value());

        Map<?, ?> body = (Map<?, ?>) response.getBody();

        assertNotNull(body);
        assertEquals("SUCCESS", body.get("status"));
        assertEquals(fakeJevResult, body.get("jevAnalysis"));

        System.out.println("Jev 결과 추가 테스트: PASS");
    }

    @Test
    void testOriginalUrlTransfer() {
        when(jevAnalysisService.analyze(anyString()))
                .thenReturn(Map.of("risk_level", "safe"));

        controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        verify(jevAnalysisService).analyze(RAW_URL);
        verify(jevAnalysisService, never()).analyze(NORMALIZED_URL);

        System.out.println("Jev 원본 URL 전달 테스트: PASS");
    }

    @Test
    void testExistingAnalysisPreserved() {
        when(jevAnalysisService.analyze(RAW_URL))
                .thenReturn(Map.of("risk_level", "safe"));

        ResponseEntity<?> response =
                controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        Map<?, ?> body = (Map<?, ?>) response.getBody();

        assertNotNull(body);
        assertEquals("SUCCESS", body.get("status"));
        assertEquals(NORMALIZED_URL, body.get("normalizedUrl"));
        assertEquals("example.com", body.get("domain"));
        assertTrue(body.containsKey("ruleAnalysis"));
        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                body.get("reputationStatus")
        );
        assertEquals(false, body.get("phishingUrlMatched"));

        verify(analysisService).analyze(
                RAW_URL,
                NORMALIZED_URL,
                "example.com"
        );

        System.out.println("기존 분석 결과 유지 테스트: PASS");
    }

    
@Test
void testJevFailureDoesNotBreakExistingAnalysis() {

    // Jev 서버 장애 상황 가정
    when(jevAnalysisService.analyze(RAW_URL))
            .thenThrow(new IllegalStateException("Mock Jev error"));

    ResponseEntity<?> response =
            controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

    // 1. 전체 API는 정상 응답해야 함
    assertEquals(200, response.getStatusCode().value());

    Map<?, ?> body = (Map<?, ?>) response.getBody();

    assertNotNull(body);
    assertEquals("SUCCESS", body.get("status"));

    // 2. URL 정규화 결과 유지
    assertEquals(
            NORMALIZED_URL,
            body.get("normalizedUrl")
    );

    assertEquals(
            "example.com",
            body.get("domain")
    );

    // 3. 기존 분석 결과 유지
    assertTrue(body.containsKey("ruleAnalysis"));

    assertEquals(
            DomainReputationService.ReputationStatus.UNKNOWN,
            body.get("reputationStatus")
    );

    assertEquals(
            false,
            body.get("phishingUrlMatched")
    );

    // 4. Jev 결과만 UNAVAILABLE 처리
    Map<?, ?> jevResult =
            (Map<?, ?>) body.get("jevAnalysis");

    assertNotNull(jevResult);

    assertEquals(
            "UNAVAILABLE",
            jevResult.get("status")
    );

    assertEquals(
            "Jev 분석을 사용할 수 없습니다.",
            jevResult.get("message")
    );

    // 5. 기존 분석 서비스가 정상 호출되었는지 검증
    verify(analysisService).analyze(
            RAW_URL,
            NORMALIZED_URL,
            "example.com"
    );

    // 6. Jev에는 원본 URL이 전달되었는지 검증
    verify(jevAnalysisService).analyze(RAW_URL);

    System.out.println(
            "Jev 장애 시 기존 분석 결과 유지 테스트: PASS"
    );
}

}
