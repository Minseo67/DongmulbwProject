
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RiskExplanationServiceTest {

    private final RiskExplanationService service =
            new RiskExplanationService();

    private RuleAnalysisResult rule(String level) {
        return new RuleAnalysisResult(
                14, 0, 2, 0,
                false, false, false, false,
                false, false, false,
                0, 0.0, level, List.of()
        );
    }

    private MlAnalysisService.MlResult ml(float probability) {
        return new MlAnalysisService.MlResult(
                "rf_f_v1",
                probability,
                probability >= 0.5f ? 1 : 0,
                0.5f
        );
    }

    private FinalRiskAssessmentService.FinalAssessment assessment(
            String level,
            String status,
            String reason,
            boolean jevUsed) {

        return new FinalRiskAssessmentService.FinalAssessment(
                level, status, reason, jevUsed, "priority-v1"
        );
    }

    private Map<String, Object> jev(String level) {
        return Map.of(
                "status", "COMPLETED",
                "jevAnalysis", Map.of("risk_level", level)
        );
    }

    @Test
    void safeAgreementGeneratesSafeExplanation() {
        var result = service.generate(
                assessment("SAFE", "COMPLETE",
                        "RULE_RF_AGREEMENT", false),
                rule("SAFE"),
                ml(0.10f),
                null
        );

        assertTrue(result.title().contains("위험 징후"));
        assertTrue(result.description().contains("낮은 위험 가능성"));
    }

    @Test
    void dangerAgreementGeneratesDangerExplanation() {
        var result = service.generate(
                assessment("DANGER", "COMPLETE",
                        "RULE_RF_AGREEMENT", false),
                rule("DANGER"),
                ml(0.90f),
                null
        );

        assertTrue(result.title().contains("위험 가능성"));
        assertTrue(result.description().contains("높은 위험"));
    }

    @Test
    void conflictWithJevSafeGeneratesCautionExplanation() {
        var result = service.generate(
                assessment("CAUTION", "COMPLETE",
                        "RULE_RF_CONFLICT", true),
                rule("SAFE"),
                ml(0.93f),
                jev("safe")
        );

        assertEquals("주의가 필요한 URL입니다.", result.title());
        assertTrue(result.description().contains("서로 다르게"));
        assertTrue(result.description().contains("높은 악성 가능성"));
        assertTrue(result.description().contains("안전한 것으로"));
    }

    @Test
    void skippedJevDoesNotClaimAdditionalAnalysis() {
        var result = service.generate(
                assessment("CAUTION", "COMPLETE",
                        "RULE_RF_CONFLICT", false),
                rule("SAFE"),
                ml(0.93f),
                Map.of("status", "SKIPPED")
        );

        assertFalse(result.description().contains("추가 AI 분석에서는"));
        assertTrue(result.description().contains("주의 등급"));
    }

    @Test
    void unavailableJevDoesNotClaimAdditionalAnalysis() {
        var result = service.generate(
                assessment("CAUTION", "COMPLETE",
                        "RULE_RF_CONFLICT", false),
                rule("SAFE"),
                ml(0.93f),
                Map.of("status", "UNAVAILABLE")
        );

        assertFalse(result.description().contains("추가 AI 분석에서는"));
        assertTrue(result.description().contains("주의 등급"));
    }

    @Test
    void rfUnavailableGeneratesPartialExplanation() {
        var result = service.generate(
                assessment("CAUTION", "PARTIAL",
                        "RF_UNAVAILABLE", false),
                rule("SAFE"),
                null,
                null
        );

        assertTrue(result.description().contains("완료하지 못해"));
        assertTrue(result.description().contains("주의 등급"));
    }

    @Test
    void phishingMatchGeneratesWarning() {
        var result = service.generate(
                assessment("DANGER", "COMPLETE",
                        "PHISHING_URL_MATCH", false),
                rule("SAFE"),
                ml(0.10f),
                null
        );

        assertTrue(result.description().contains("피싱 URL 목록"));
        assertTrue(result.description().contains("개인정보"));
    }

    @Test
    void jevUnknownGeneratesUncertaintyExplanation() {
        var result = service.generate(
                assessment("CAUTION", "COMPLETE",
                        "RULE_RF_CONFLICT", false),
                rule("SAFE"),
                ml(0.93f),
                jev("unknown")
        );

        assertTrue(result.description().contains("명확히"));
        assertTrue(result.description().contains("주의 등급"));
    }
}
