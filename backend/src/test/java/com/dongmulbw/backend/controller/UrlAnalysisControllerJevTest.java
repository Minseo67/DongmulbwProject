
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.repository.UrlRepository;

import com.dongmulbw.backend.service.IntegratedUrlAnalysisService;
import com.dongmulbw.backend.service.UrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.DomainReputationService;
import com.dongmulbw.backend.service.AnalysisVersionService;
import com.dongmulbw.backend.service.UrlAnalysisCacheService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UrlAnalysisControllerJevTest {

    private UrlNormalizationService normalizationService;
    private IntegratedUrlAnalysisService integratedAnalysisService;

    private UrlRepository urlRepository;
    private AnalysisVersionService versionService;
    private UrlAnalysisCacheService cacheService;

    private UrlAnalysisController controller;

    private static final String RAW_URL =
            "HTTPS://Example.COM/login?next=home";

    private static final String NORMALIZED_URL =
            "https://example.com/login?next=home";

    private static final String DOMAIN = "example.com";

    @BeforeEach
    void setUp() {

        normalizationService = mock(UrlNormalizationService.class);
        integratedAnalysisService =
                mock(IntegratedUrlAnalysisService.class);

        urlRepository = mock(UrlRepository.class);
        versionService = mock(AnalysisVersionService.class);
        cacheService = mock(UrlAnalysisCacheService.class);

        // 변경된 Controller 생성자
        controller = new UrlAnalysisController(
                normalizationService,
                integratedAnalysisService,
                urlRepository,
                versionService,
                cacheService
        );

        UrlNormalizationResult normalized =
                new UrlNormalizationResult(
                        RAW_URL,
                        NORMALIZED_URL,
                        "https",
                        DOMAIN,
                        "test-hash",
                        "norm-v1"
                );

        when(normalizationService.normalize(RAW_URL))
                .thenReturn(normalized);

        // DB에 URL이 존재하지 않는 상황
        when(urlRepository.findByHashKeyVersionAndUrlHash(
                1, "test-hash"
        )).thenReturn(Optional.empty());

        // 통합 서비스의 기본 반환 결과
        when(integratedAnalysisService.analyze(
                RAW_URL,
                NORMALIZED_URL,
                DOMAIN
        )).thenReturn(createIntegratedResult(
                "SKIPPED",
                null,
                false
        ));
    }

    // 통합 분석 결과 생성
    private Map<String, Object> createIntegratedResult(
            String jevStatus,
            Map<String, Object> jevAnalysis,
            boolean jevTriggered) {

        UrlAnalysisService.AnalysisResult existingResult =
                new UrlAnalysisService.AnalysisResult(
                        null,
                        DomainReputationService.ReputationStatus.UNKNOWN,
                        false
                );

        Map<String, Object> result = new LinkedHashMap<>();

        result.put("status", "SUCCESS");
        result.put("ruleAnalysis", existingResult);
        result.put("mlAnalysis", null);

        result.put("jevTriggered", jevTriggered);
        result.put("jevStatus", jevStatus);
        result.put("jevAnalysis", jevAnalysis);
        result.put("jevElapsedMs", null);

        return result;
    }

    @Test
    void testJevResultIncluded() {

        Map<String, Object> fakeJevResult = Map.of(
                "risk_level", "safe",
                "confidence", 0.72,
                "model", "jev-test",
                "cached", false
        );

        when(integratedAnalysisService.analyze(
                RAW_URL,
                NORMALIZED_URL,
                DOMAIN
        )).thenReturn(createIntegratedResult(
                "COMPLETED",
                fakeJevResult,
                true
        ));

        ResponseEntity<?> response =
                controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        assertEquals(200, response.getStatusCode().value());

        Map<?, ?> body = (Map<?, ?>) response.getBody();

        assertNotNull(body);
        assertEquals("SUCCESS", body.get("status"));

        assertEquals(true, body.get("jevTriggered"));
        assertEquals("COMPLETED", body.get("jevStatus"));
        assertEquals(fakeJevResult, body.get("jevAnalysis"));

        // 기존 DB 및 캐시 정보 유지
        assertEquals(false, body.get("urlExists"));
        assertNull(body.get("urlId"));
        assertEquals(false, body.get("cacheHit"));
    }

    @Test
    void testOriginalUrlTransfer() {

        controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        // 통합 서비스에 세 가지 URL 정보가 정확히 전달되는지 검증
        verify(integratedAnalysisService).analyze(
                RAW_URL,
                NORMALIZED_URL,
                DOMAIN
        );

        verify(integratedAnalysisService, times(1))
                .analyze(anyString(), anyString(), anyString());
    }

    @Test
    void testExistingAnalysisPreserved() {

        ResponseEntity<?> response =
                controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        assertEquals(200, response.getStatusCode().value());

        Map<?, ?> body = (Map<?, ?>) response.getBody();

        assertNotNull(body);

        assertEquals("SUCCESS", body.get("status"));
        assertEquals(NORMALIZED_URL, body.get("normalizedUrl"));
        assertEquals(DOMAIN, body.get("domain"));

        // 기존 분석 항목 유지
        assertTrue(body.containsKey("ruleAnalysis"));

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                body.get("reputationStatus")
        );

        assertEquals(false, body.get("phishingUrlMatched"));

        // 새 분석 항목 포함
        assertTrue(body.containsKey("mlAnalysis"));
        assertEquals(false, body.get("jevTriggered"));
        assertEquals("SKIPPED", body.get("jevStatus"));
        assertNull(body.get("jevAnalysis"));

        verify(integratedAnalysisService).analyze(
                RAW_URL,
                NORMALIZED_URL,
                DOMAIN
        );
    }

    @Test
    void testJevFailureDoesNotBreakExistingAnalysis() {

        // JEV 호출이 실패한 경우의 통합 서비스 반환값
        when(integratedAnalysisService.analyze(
                RAW_URL,
                NORMALIZED_URL,
                DOMAIN
        )).thenReturn(createIntegratedResult(
                "UNAVAILABLE",
                null,
                true
        ));

        ResponseEntity<?> response =
                controller.analyzeUrl(new UrlCollectRequest(RAW_URL));

        // 전체 API는 정상 응답
        assertEquals(200, response.getStatusCode().value());

        Map<?, ?> body = (Map<?, ?>) response.getBody();

        assertNotNull(body);
        assertEquals("SUCCESS", body.get("status"));

        // 기존 URL 정보 유지
        assertEquals(NORMALIZED_URL, body.get("normalizedUrl"));
        assertEquals(DOMAIN, body.get("domain"));

        // 기존 분석 결과 유지
        assertTrue(body.containsKey("ruleAnalysis"));

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                body.get("reputationStatus")
        );

        assertEquals(false, body.get("phishingUrlMatched"));

        // JEV만 사용 불가 상태
        assertEquals(true, body.get("jevTriggered"));
        assertEquals("UNAVAILABLE", body.get("jevStatus"));
        assertNull(body.get("jevAnalysis"));

        verify(integratedAnalysisService).analyze(
                RAW_URL,
                NORMALIZED_URL,
                DOMAIN
        );
    }
}
