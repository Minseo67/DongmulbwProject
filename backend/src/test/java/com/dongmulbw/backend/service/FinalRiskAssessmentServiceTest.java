
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FinalRiskAssessmentServiceTest {

    private final FinalRiskAssessmentService service =
            new FinalRiskAssessmentService();

    // 테스트용 규칙 기반 분석 결과
    private RuleAnalysisResult rule(String riskLevel) {
        return new RuleAnalysisResult(
                14, 0, 2, 0,
                false, false, false, false,
                false, false, false,
                0, 0.0, riskLevel, List.of()
        );
    }

    // 테스트용 RF 모델 분석 결과
    private MlAnalysisService.MlResult ml(float probability) {
        return new MlAnalysisService.MlResult(
                "rf_f_v1",
                probability,
                probability >= 0.5f ? 1 : 0,
                0.5f
        );
    }

    // 테스트용 JEV 응답
    private Map<String, Object> jev(String status, String riskLevel) {
        return Map.of(
                "status", status,
                "jevAnalysis", Map.of("risk_level", riskLevel)
        );
    }

    @Test
    void bothSafeReturnsSafe() {
        var result = service.assess(
                rule("SAFE"), ml(0.10f), false, null);

        assertEquals("SAFE", result.riskLevel());
        assertEquals("RULE_RF_AGREEMENT", result.decisionReason());
        assertFalse(result.jevUsed());
    }

    @Test
    void bothDangerReturnsDanger() {
        var result = service.assess(
                rule("DANGER"), ml(0.90f), false, null);

        assertEquals("DANGER", result.riskLevel());
        assertEquals("RULE_RF_AGREEMENT", result.decisionReason());
    }

    @Test
    void conflictWithJevSafeReturnsCaution() {
        var result = service.assess(
                rule("SAFE"),
                ml(0.93f),
                false,
                jev("COMPLETED", "safe")
        );

        assertEquals("CAUTION", result.riskLevel());
        assertEquals("RULE_RF_CONFLICT", result.decisionReason());
        assertTrue(result.jevUsed());
    }

    @Test
    void conflictWithJevDangerReturnsDanger() {
        var result = service.assess(
                rule("SAFE"),
                ml(0.93f),
                false,
                jev("COMPLETED", "danger")
        );

        assertEquals("DANGER", result.riskLevel());
        assertEquals("JEV_SUPPORTS_DANGER", result.decisionReason());
        assertTrue(result.jevUsed());
    }

    @Test
    void skippedJevDoesNotAffectAssessment() {
        var result = service.assess(
                rule("SAFE"),
                ml(0.93f),
                false,
                Map.of("status", "SKIPPED")
        );

        assertEquals("CAUTION", result.riskLevel());
        assertFalse(result.jevUsed());
    }

    @Test
    void unavailableJevDoesNotAffectAssessment() {
        var result = service.assess(
                rule("SAFE"),
                ml(0.93f),
                false,
                Map.of("status", "UNAVAILABLE")
        );

        assertEquals("CAUTION", result.riskLevel());
        assertFalse(result.jevUsed());
    }

    @Test
    void rfUnavailableReturnsPartial() {
        var result = service.assess(
                rule("SAFE"), null, false, null);

        assertEquals("CAUTION", result.riskLevel());
        assertEquals("PARTIAL", result.assessmentStatus());
        assertEquals("RF_UNAVAILABLE", result.decisionReason());
    }

    @Test
    void phishingMatchOverridesOtherResults() {
        var result = service.assess(
                rule("SAFE"),
                ml(0.10f),
                true,
                null
        );

        assertEquals("DANGER", result.riskLevel());
        assertEquals("PHISHING_URL_MATCH", result.decisionReason());
    }

    @Test
    void jevUnknownDoesNotAffectAssessment() {
        var result = service.assess(
                rule("SAFE"),
                ml(0.93f),
                false,
                jev("COMPLETED", "unknown")
        );

        assertEquals("CAUTION", result.riskLevel());
        assertFalse(result.jevUsed());
    }
}
