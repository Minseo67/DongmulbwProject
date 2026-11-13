
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.service.JevAnalysisService;
import com.dongmulbw.backend.service.UrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.DomainReputationService;
import com.dongmulbw.backend.repository.UrlRepository;
import com.dongmulbw.backend.service.AnalysisVersionService;
import com.dongmulbw.backend.service.UrlAnalysisCacheService;

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

    UrlRepository urlRepository = mock(UrlRepository.class);
    AnalysisVersionService analysisVersionService =
            mock(AnalysisVersionService.class);
    UrlAnalysisCacheService urlAnalysisCacheService =
            mock(UrlAnalysisCacheService.class);

    controller = new UrlAnalysisController(
            normalizationService,
            analysisService,
            jevAnalysisService,
            urlRepository,
            analysisVersionService,
            urlAnalysisCacheService
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
        when(jevAnalysisService.analyze(RAW_URL))
                .thenThrow(new IllegalStateException("Mock Jev error"));

        ResponseEntity<?> response =
                controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        assertEquals(200, response.getStatusCode().value());

        Map<?, ?> body = (Map<?, ?>) response.getBody();

        assertNotNull(body);
        assertEquals("SUCCESS", body.get("status"));
        assertEquals(NORMALIZED_URL, body.get("normalizedUrl"));

        Map<?, ?> jevResult = (Map<?, ?>) body.get("jevAnalysis");

        assertNotNull(jevResult);
        assertEquals("UNAVAILABLE", jevResult.get("status"));

        verify(analysisService).analyze(
                RAW_URL,
                NORMALIZED_URL,
                "example.com"
        );

        System.out.println("Jev 장애 대응 테스트: PASS");
    }
}
