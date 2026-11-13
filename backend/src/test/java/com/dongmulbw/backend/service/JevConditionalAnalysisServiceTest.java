
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

        // 실제 JEV API 대신 Mockito 가짜 객체 사용
        jevTriggerService = new JevTriggerService();
        jevAnalysisService = mock(JevAnalysisService.class);

        service = new JevConditionalAnalysisService(
                jevTriggerService,
                jevAnalysisService
        );
    }

    /**
     * 1. 조건 A: 점수 차이 40점 이상
     *
     * 규칙 85점, RF 15점
     * 차이 70점 → JEV 실행
     */
    @Test
    void shouldCallJevWhenScoresConflict() {

        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenReturn(Map.of("risk_level", "danger"));

        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("COMPLETED", result.get("status"));
        assertNotNull(result.get("jevAnalysis"));

        verify(jevAnalysisService, times(1))
                .analyze(url);
    }

    /**
     * 2. 조건 A·B 모두 미충족
     *
     * 규칙 10점, RF 10점
     * 차이 0점, 평균 10점
     * → JEV 생략
     */
    @Test
    void shouldSkipJevWhenBothAreSafe() {

        String url = "https://example.com";

        Map<String, Object> result =
                service.analyze(url, 10, 0.10);

        assertEquals(false, result.get("jevTriggered"));
        assertEquals("SKIPPED", result.get("status"));

        assertEquals(
                "SCORE_CONDITIONS_NOT_MET",
                result.get("skipReason")
        );

        assertNull(result.get("jevAnalysis"));
        assertNull(result.get("elapsedMs"));

        // 실제 JEV 분석 메서드 호출 0회
        verify(jevAnalysisService, never())
                .analyze(anyString());
    }

    /**
     * 3. 조건 B: 평균 점수 40~60점
     *
     * 규칙 50점, RF 50점
     * 평균 50점 → JEV 실행
     */
    @Test
    void shouldCallJevWhenScoreIsUncertain() {

        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenReturn(Map.of("risk_level", "caution"));

        Map<String, Object> result =
                service.analyze(url, 50, 0.50);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("COMPLETED", result.get("status"));

        verify(jevAnalysisService, times(1))
                .analyze(url);
    }

    /**
     * 4. JEV 호출 실패
     *
     * 오류가 발생해도 전체 분석 흐름을
     * 중단하지 않고 UNAVAILABLE 반환
     */
    @Test
    void shouldHandleJevFailure() {

        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenThrow(
                        new RuntimeException("API 오류")
                );

        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("UNAVAILABLE", result.get("status"));
        assertNull(result.get("jevAnalysis"));

        assertNotNull(result.get("elapsedMs"));

        verify(jevAnalysisService, times(1))
                .analyze(url);
    }

    /**
     * 5. JEV 응답이 null인 경우
     *
     * 호출은 되었지만 응답이 없으므로
     * UNAVAILABLE 반환
     */
    @Test
    void shouldHandleNullJevResponse() {

        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenReturn(null);

        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("UNAVAILABLE", result.get("status"));
        assertNull(result.get("jevAnalysis"));

        verify(jevAnalysisService, times(1))
                .analyze(url);
    }

    /**
     * 6. JEV 응답이 빈 Map인 경우
     *
     * 비어 있는 응답은 정상 분석 결과로
     * 처리하지 않음
     */
    @Test
    void shouldHandleEmptyJevResponse() {

        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenReturn(Map.of());

        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("UNAVAILABLE", result.get("status"));
        assertNull(result.get("jevAnalysis"));

        verify(jevAnalysisService, times(1))
                .analyze(url);
    }

    /**
     * 7. JEV 정상 완료 시 실행 시간 기록
     */
    @Test
    void shouldRecordElapsedTimeWhenCompleted() {

        String url = "https://example.com";

        when(jevAnalysisService.analyze(url))
                .thenReturn(Map.of("risk_level", "safe"));

        Map<String, Object> result =
                service.analyze(url, 85, 0.15);

        assertEquals("COMPLETED", result.get("status"));
        assertNotNull(result.get("elapsedMs"));

        assertTrue(
                ((Number) result.get("elapsedMs"))
                        .longValue() >= 0
        );

        verify(jevAnalysisService, times(1))
                .analyze(url);
    }

    /**
     * 8. 규칙 기반 점수가 잘못된 경우
     *
     * 유효하지 않은 입력값이면
     * JEV를 호출하지 않고 예외 발생
     */
    @Test
    void shouldRejectInvalidRuleScore() {

        String url = "https://example.com";

        assertThrows(
                IllegalArgumentException.class,
                () -> service.analyze(url, 101, 0.50)
        );

        verifyNoInteractions(jevAnalysisService);
    }

    /**
     * 9. RF 확률이 잘못된 경우
     *
     * RF 확률은 0~1 범위여야 함
     */
    @Test
    void shouldRejectInvalidRfProbability() {

        String url = "https://example.com";

        assertThrows(
                IllegalArgumentException.class,
                () -> service.analyze(url, 50, 1.50)
        );

        verifyNoInteractions(jevAnalysisService);
    }
}
