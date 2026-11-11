
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JevConditionalAnalysisServiceTest {

    private JevTriggerService jevTriggerService;
    private JevAnalysisService jevAnalysisService;
    private JevConditionalAnalysisService service;

    @BeforeEach
    void setUp() {
        // 실제 JEV API 대신 가짜 객체 사용
        jevTriggerService = new JevTriggerService();
        jevAnalysisService = mock(JevAnalysisService.class);

        service = new JevConditionalAnalysisService(
                jevTriggerService,
                jevAnalysisService
        );
    }

    @Test
    void shouldCallJevWhenScoresConflict() {
        String url = "https://example.com";

        // JEV API가 정상 응답했다고 가정
        when(jevAnalysisService.analyze(url))
                .thenReturn(Map.of("risk_level", "danger"));

        // 규칙 85점, RF 15% → JEV 실행
        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("COMPLETED", result.get("status"));

        // JEV가 정확히 한 번 호출되었는지 확인
        verify(jevAnalysisService, times(1)).analyze(url);
    }

    @Test
    void shouldSkipJevWhenBothAreSafe() {
        String url = "https://example.com";

        // 규칙 10점, RF 10% → JEV 생략
        Map<String, Object> result =
                service.analyze(url, 10, 0.10);

        assertEquals(false, result.get("jevTriggered"));
        assertEquals("SKIPPED", result.get("status"));
        assertNull(result.get("jevAnalysis"));

        // JEV API가 호출되지 않았는지 확인
        verify(jevAnalysisService, never()).analyze(anyString());
    }

    @Test
    void shouldCallJevWhenScoreIsUncertain() {
        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenReturn(Map.of("risk_level", "caution"));

        // 통합 점수 50점 → JEV 실행
        Map<String, Object> result =
                service.analyze(url, 50, 0.50);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("COMPLETED", result.get("status"));

        verify(jevAnalysisService, times(1)).analyze(url);
    }

    @Test
    void shouldHandleJevFailure() {
        String url = "https://example.com";

        // JEV 호출 실패 상황 가정
        when(jevAnalysisService.analyze(url))
                .thenThrow(new RuntimeException("API 오류"));

        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("UNAVAILABLE", result.get("status"));
        assertNull(result.get("jevAnalysis"));

        verify(jevAnalysisService, times(1)).analyze(url);
    }
}
