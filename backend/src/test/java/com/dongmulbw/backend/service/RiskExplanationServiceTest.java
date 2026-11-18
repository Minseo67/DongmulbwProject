
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RiskExplanationServiceTest {

    private final RiskExplanationService service =
            new RiskExplanationService();

    // 규칙 기반 결과 생성
    private RuleAnalysisResult rule(String level) {

        return new RuleAnalysisResult(
                14, 0, 2, 0,
                false, false, false, false,
                false, false, false,
                0, 0.0, level, List.of()
        );
    }

    // RF 분석 결과 생성
    private MlAnalysisService.MlResult ml(float probability) {

        return new MlAnalysisService.MlResult(
                "rf_f_v1",
                probability,
                probability >= 0.5f ? 1 : 0,
                0.5f
        );
    }

    // 최종 판단 결과 생성
    private FinalRiskAssessmentService.FinalAssessment assessment(
            String level,
            String reason,
            boolean jevUsed) {

        return new FinalRiskAssessmentService.FinalAssessment(
                level,
                "COMPLETE",
                reason,
                jevUsed,
                "priority-v1"
        );
    }

    // JEV 완료 결과 생성
    private Map<String, Object> jev(String level) {

        return Map.of(
                "status", "COMPLETED",
                "jevAnalysis",
                Map.of("risk_level", level)
        );
    }

    // 규칙·RF 불일치 설명 생성
    private String conflict(
            String ruleLevel,
            float probability,
            Map<String, Object> jevResult) {

        return service.generate(
                assessment(
                        "CAUTION",
                        "RULE_RF_CONFLICT",
                        false
                ),
                rule(ruleLevel),
                ml(probability),
                jevResult
        ).description();
    }

    // 1. 규칙 SAFE / RF SAFE
    @Test
    void safeAgreement() {

        var x = service.generate(
                assessment(
                        "SAFE",
                        "RULE_RF_AGREEMENT",
                        false
                ),
                rule("SAFE"),
                ml(.10f),
                Map.of("status", "SKIPPED")
        );

        assertTrue(
                x.description().contains("낮은 위험")
        );

        assertTrue(
                x.description().contains("실행되지 않았습니다")
        );
    }

    // 2. 규칙 CAUTION / RF CAUTION
    @Test
    void cautionAgreement() {

        var x = service.generate(
                assessment(
                        "CAUTION",
                        "RULE_RF_AGREEMENT",
                        false
                ),
                rule("CAUTION"),
                ml(.50f),
                Map.of("status", "SKIPPED")
        );

        assertTrue(
                x.description().contains("주의가 필요한 수준")
        );
    }

    // 3. 규칙 DANGER / RF DANGER
    @Test
    void dangerAgreement() {

        var x = service.generate(
                assessment(
                        "DANGER",
                        "RULE_RF_AGREEMENT",
                        false
                ),
                rule("DANGER"),
                ml(.90f),
                Map.of("status", "SKIPPED")
        );

        assertTrue(
                x.description().contains("높은 위험")
        );
    }

    // 4. 등급 일치 시 JEV가 실행됐더라도
    // 최종 판단은 규칙·RF 일치 결과를 우선
    @Test
    void agreementEvenIfJevCompletedDoesNotClaimJevDecidedFinalGrade() {

        var x = service.generate(
                assessment(
                        "SAFE",
                        "RULE_RF_AGREEMENT",
                        false
                ),
                rule("SAFE"),
                ml(.10f),
                jev("danger")
        );

        assertTrue(
                x.description().contains("일치한 판단을 우선 적용")
        );
    }

    // 5. 규칙 SAFE / RF CAUTION
    @Test
    void safeCautionConflict() {

        assertTrue(
                conflict("SAFE", .50f, null)
                        .contains("RF는 주의 수준")
        );
    }

    // 6. 규칙 SAFE / RF DANGER
    @Test
    void safeDangerConflict() {

        assertTrue(
                conflict("SAFE", .90f, null)
                        .contains("높은 악성 가능성")
        );
    }

    // 7. 규칙 CAUTION / RF SAFE
    @Test
    void cautionSafeConflict() {

        assertTrue(
                conflict("CAUTION", .10f, null)
                        .contains("RF는 낮은 위험")
        );
    }

    // 8. 규칙 CAUTION / RF DANGER
    @Test
    void cautionDangerConflict() {

        assertTrue(
                conflict("CAUTION", .90f, null)
                        .contains("RF는 높은 악성")
        );
    }

    // 9. 규칙 DANGER / RF SAFE
    @Test
    void dangerSafeConflict() {

        assertTrue(
                conflict("DANGER", .10f, null)
                        .contains("높은 위험 가능성")
        );
    }

    // 10. 규칙 DANGER / RF CAUTION
    @Test
    void dangerCautionConflict() {

        assertTrue(
                conflict("DANGER", .50f, null)
                        .contains("RF는 주의 수준")
        );
    }

    // 11. 불일치 + JEV SAFE
    @Test
    void jevSafeConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .90f,
                        jev("safe")
                ).contains("JEV는 낮은 위험")
        );
    }

    // 12. 불일치 + JEV CAUTION
    @Test
    void jevCautionConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .90f,
                        jev("caution")
                ).contains("JEV는 주의")
        );
    }

    // 13. 불일치 + JEV DANGER
    // 규칙과 RF 모두 DANGER가 아니면 CAUTION 유지
    @Test
    void jevDangerWithoutOtherDangerConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .50f,
                        jev("danger")
                ).contains("JEV만으로")
        );
    }

    // 14. JEV 결과 UNKNOWN
    @Test
    void jevUnknownConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .90f,
                        jev("unknown")
                ).contains("유효한 위험 등급")
        );
    }

    // 15. JEV가 DANGER 판단을 뒷받침
    @Test
    void jevSupportsDanger() {

        var x = service.generate(
                assessment(
                        "DANGER",
                        "JEV_SUPPORTS_DANGER",
                        true
                ),
                rule("DANGER"),
                ml(.10f),
                jev("danger")
        );

        assertTrue(
                x.description().contains("JEV가 뒷받침")
        );
    }

    // 16. 점수 조건 미충족으로 JEV 생략
    @Test
    void scoreSkipConflict() {

        var x = conflict(
                "SAFE",
                .50f,
                Map.of(
                        "status", "SKIPPED",
                        "skipReason",
                        "SCORE_CONDITIONS_NOT_MET"
                )
        );

        assertTrue(
                x.contains("점수 차이 40점")
        );
    }

    // 17. 일반 JEV 생략
    @Test
    void skippedConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .90f,
                        Map.of("status", "SKIPPED")
                ).contains("실행되지 않았습니다")
        );
    }

    // 18. JEV 응답 없음
    @Test
    void unavailableConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .90f,
                        Map.of("status", "UNAVAILABLE")
                ).contains("유효한 결과를 얻지 못했습니다")
        );
    }

    // 19. JEV 실패
    @Test
    void failedConflict() {

        assertTrue(
                conflict(
                        "SAFE",
                        .90f,
                        Map.of("status", "FAILED")
                ).contains("유효한 결과를 얻지 못했습니다")
        );
    }

    // 20. JEV 완료지만 risk_level 누락
    @Test
    void completedMissingLevel() {

        var x = conflict(
                "SAFE",
                .90f,
                Map.of(
                        "status", "COMPLETED",
                        "jevAnalysis",
                        Map.of("message", "empty")
                )
        );

        assertTrue(
                x.contains("유효한 위험 등급")
        );
    }

    // 21. RF 분석 실패
    @Test
    void rfUnavailable() {

        var x = service.generate(
                new FinalRiskAssessmentService.FinalAssessment(
                        "CAUTION",
                        "PARTIAL",
                        "RF_UNAVAILABLE",
                        false,
                        "priority-v1"
                ),
                rule("SAFE"),
                null,
                null
        );

        assertTrue(
                x.description().contains("RF")
        );

        assertTrue(
                x.description().contains("JEV 보조 분석도 수행하지")
        );
    }

    // 22. 피싱 블랙리스트 일치
    @Test
    void phishingMatch() {

        var x = service.generate(
                assessment(
                        "DANGER",
                        "PHISHING_URL_MATCH",
                        false
                ),
                rule("SAFE"),
                ml(.10f),
                Map.of("status", "SKIPPED")
        );

        assertTrue(
                x.description().contains("피싱 URL 목록")
        );

        assertTrue(
                x.description().contains("JEV 보조 분석은 수행하지")
        );
    }

    // 23. 최종 판단 결과 null
    @Test
    void nullAssessmentRejected() {

        assertThrows(
                IllegalArgumentException.class,
                () -> service.generate(
                        null,
                        rule("SAFE"),
                        ml(.10f),
                        null
                )
        );
    }

    // 24. 규칙 기반 결과 null
    @Test
    void nullRuleRejected() {

        assertThrows(
                IllegalArgumentException.class,
                () -> service.generate(
                        assessment(
                                "SAFE",
                                "RULE_RF_AGREEMENT",
                                false
                        ),
                        null,
                        ml(.10f),
                        null
                )
        );
    }
}
