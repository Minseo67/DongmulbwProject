
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class IntegratedUrlAnalysisServiceTest {

    @Mock
    private UrlAnalysisService urlAnalysisService;

    @Mock
    private MlAnalysisService mlAnalysisService;

    @Mock
    private JevConditionalAnalysisService jevConditionalAnalysisService;

    private IntegratedUrlAnalysisService service;

    @BeforeEach
    void setUp() {

        MockitoAnnotations.openMocks(this);

        service = new IntegratedUrlAnalysisService(
                urlAnalysisService,
                mlAnalysisService,
                jevConditionalAnalysisService,
                new FinalRiskAssessmentService(),
                new RiskExplanationService()
        );
    }

    // 규칙 기반 결과 생성
    private RuleAnalysisResult rule(
            String level,
            double score) {

        return new RuleAnalysisResult(
                14, 0, 2, 0,
                false, false, false, false,
                false, false, false,
                0, score, level, List.of()
        );
    }

    // RF 분석 결과 생성
    private MlAnalysisService.MlResult ml(float probability) {

        return new MlAnalysisService.MlResult(
                "rf_f_v1",
                probability,
                probability >= .5f ? 1 : 0,
                .5f
        );
    }

    // URL 분석 결과 설정
    private void mockRuleAnalysis(
            boolean phishingMatched,
            String ruleLevel,
            double ruleScore) {

        var analysis = new UrlAnalysisService.AnalysisResult(
                rule(ruleLevel, ruleScore),
                null,
                phishingMatched
        );

        when(urlAnalysisService.analyze(
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(analysis);
    }

    // JEV 생략 결과
    private Map<String, Object> skippedJev() {

        Map<String, Object> result =
                new LinkedHashMap<>();

        result.put("jevTriggered", false);
        result.put("status", "SKIPPED");
        result.put(
                "skipReason",
                "SCORE_CONDITIONS_NOT_MET"
        );
        result.put("jevAnalysis", null);
        result.put("elapsedMs", null);

        return result;
    }

    // JEV 정상 완료 결과
    private Map<String, Object> completedJev(
            String level) {

        Map<String, Object> result =
                new LinkedHashMap<>();

        result.put("jevTriggered", true);
        result.put("status", "COMPLETED");
        result.put(
                "jevAnalysis",
                Map.of("risk_level", level)
        );
        result.put("elapsedMs", 100L);

        return result;
    }

    /**
     * 1. 피싱 블랙리스트 일치
     *
     * JEV 조건 검사와 외부 호출을 모두 생략해야 함
     */
    @Test
    void phishingBlacklistSkipsJev() throws Exception {

        mockRuleAnalysis(true, "SAFE", 10.0);

        when(mlAnalysisService.analyze(anyString()))
                .thenReturn(ml(.90f));

        Map<String, Object> result = service.analyze(
                "https://phishing.example",
                "https://phishing.example",
                "phishing.example"
        );

        // JEV 조건부 분석 서비스 호출 0회
        verify(
                jevConditionalAnalysisService,
                never()
        ).analyze(
                anyString(),
                anyDouble(),
                anyDouble()
        );

        assertEquals(
                false,
                result.get("jevTriggered")
        );

        assertEquals(
                "SKIPPED",
                result.get("jevStatus")
        );

        assertEquals(
                "PHISHING_URL_MATCH",
                result.get("jevSkipReason")
        );

        var assessment =
                (FinalRiskAssessmentService.FinalAssessment)
                        result.get("finalAssessment");

        assertEquals("DANGER", assessment.riskLevel());
        assertEquals(
                "PHISHING_URL_MATCH",
                assessment.decisionReason()
        );
    }

    /**
     * 2. 점수 차이 40점 이상
     *
     * 통합 서비스가 JEV 조건부 분석 서비스에
     * 올바른 점수를 전달하는지 검증
     */
    @Test
    void scoreDifferenceCallsJevConditionalService()
            throws Exception {

        mockRuleAnalysis(false, "SAFE", 10.0);

        when(mlAnalysisService.analyze(anyString()))
                .thenReturn(ml(.90f));

        when(jevConditionalAnalysisService.analyze(
                anyString(),
                anyDouble(),
                anyDouble()
        )).thenReturn(completedJev("DANGER"));

        Map<String, Object> result = service.analyze(
                "https://example.com",
                "https://example.com",
                "example.com"
        );

        verify(jevConditionalAnalysisService)
                .analyze(
                        eq("https://example.com"),
                        eq(10.0),
                        eq((double) .90f)
                );

        assertEquals(
                true,
                result.get("jevTriggered")
        );

        assertEquals(
                "COMPLETED",
                result.get("jevStatus")
        );

        var assessment =
                (FinalRiskAssessmentService.FinalAssessment)
                        result.get("finalAssessment");

        assertEquals("DANGER", assessment.riskLevel());
        assertEquals(
                "JEV_SUPPORTS_DANGER",
                assessment.decisionReason()
        );
    }

    /**
     * 3. 평균 점수 40~60점
     *
     * 규칙 기반과 RF 점수가 비슷하더라도
     * 조건부 분석 서비스를 호출하는지 확인
     */
    @Test
    void uncertainAverageCallsJevConditionalService()
            throws Exception {

        mockRuleAnalysis(false, "CAUTION", 45.0);

        when(mlAnalysisService.analyze(anyString()))
                .thenReturn(ml(.50f));

        when(jevConditionalAnalysisService.analyze(
                anyString(),
                anyDouble(),
                anyDouble()
        )).thenReturn(completedJev("SAFE"));

        Map<String, Object> result = service.analyze(
                "https://example.com",
                "https://example.com",
                "example.com"
        );

        verify(jevConditionalAnalysisService)
                .analyze(
                        eq("https://example.com"),
                        eq(45.0),
                        eq(.50)
                );

        assertEquals(
                "COMPLETED",
                result.get("jevStatus")
        );

        var assessment =
                (FinalRiskAssessmentService.FinalAssessment)
                        result.get("finalAssessment");

        // 규칙·RF 모두 CAUTION이므로
        // JEV SAFE여도 기존 정책상 CAUTION
        assertEquals("CAUTION", assessment.riskLevel());
        assertEquals(
                "RULE_RF_AGREEMENT",
                assessment.decisionReason()
        );
    }

    /**
     * 4. 점수 조건 A·B 모두 미충족
     *
     * 조건부 서비스는 호출되지만
     * 내부 판단 결과 JEV가 생략된 상황을 검증
     */
    @Test
    void scoreConditionsNotMetReturnsSkipped()
            throws Exception {

        mockRuleAnalysis(false, "SAFE", 10.0);

        when(mlAnalysisService.analyze(anyString()))
                .thenReturn(ml(.20f));

        when(jevConditionalAnalysisService.analyze(
                anyString(),
                anyDouble(),
                anyDouble()
        )).thenReturn(skippedJev());

        Map<String, Object> result = service.analyze(
                "https://example.com",
                "https://example.com",
                "example.com"
        );

        verify(jevConditionalAnalysisService)
                .analyze(
                        eq("https://example.com"),
                        eq(10.0),
                        eq((double) .20f)
                );

        assertEquals(
                false,
                result.get("jevTriggered")
        );

        assertEquals(
                "SKIPPED",
                result.get("jevStatus")
        );

        assertEquals(
                "SCORE_CONDITIONS_NOT_MET",
                result.get("jevSkipReason")
        );

        var assessment =
                (FinalRiskAssessmentService.FinalAssessment)
                        result.get("finalAssessment");

        assertEquals("SAFE", assessment.riskLevel());
    }

    /**
     * 5. RF 분석 실패
     *
     * JEV 호출 없이 부분 분석 결과 반환
     */
    @Test
    void rfFailureSkipsJev() throws Exception {

        mockRuleAnalysis(false, "SAFE", 10.0);

        when(mlAnalysisService.analyze(anyString()))
                .thenThrow(
                        new IllegalStateException(
                                "RF model unavailable"
                        )
                );

        Map<String, Object> result = service.analyze(
                "https://example.com",
                "https://example.com",
                "example.com"
        );

        verify(
                jevConditionalAnalysisService,
                never()
        ).analyze(
                anyString(),
                anyDouble(),
                anyDouble()
        );

        assertEquals(
                "PARTIAL_SUCCESS",
                result.get("status")
        );

        assertEquals(
                "NOT_EVALUATED",
                result.get("jevStatus")
        );

        assertEquals(
                "RF_UNAVAILABLE",
                result.get("jevSkipReason")
        );

        var assessment =
                (FinalRiskAssessmentService.FinalAssessment)
                        result.get("finalAssessment");

        assertEquals("CAUTION", assessment.riskLevel());
    }

    /**
     * 6. 블랙리스트 일치 + RF 분석 실패
     *
     * 부분 분석이어도 블랙리스트를 우선 적용
     */
    @Test
    void phishingMatchWithRfFailureStillDanger()
            throws Exception {

        mockRuleAnalysis(true, "SAFE", 10.0);

        when(mlAnalysisService.analyze(anyString()))
                .thenThrow(
                        new IllegalStateException(
                                "RF model unavailable"
                        )
                );

        Map<String, Object> result = service.analyze(
                "https://phishing.example",
                "https://phishing.example",
                "phishing.example"
        );

        verify(
                jevConditionalAnalysisService,
                never()
        ).analyze(
                anyString(),
                anyDouble(),
                anyDouble()
        );

        var assessment =
                (FinalRiskAssessmentService.FinalAssessment)
                        result.get("finalAssessment");

        assertEquals("DANGER", assessment.riskLevel());
        assertEquals(
                "PHISHING_URL_MATCH",
                assessment.decisionReason()
        );
    }
}
