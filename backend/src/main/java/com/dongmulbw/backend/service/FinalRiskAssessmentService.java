
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;

@Service
public class FinalRiskAssessmentService {

    private static final String POLICY_VERSION = "jev-fusion-v1";

    private static final double DANGER_RULE_THRESHOLD = 60.0;
    private static final double DANGER_RF_THRESHOLD = 0.70;

    /**
     * 최신 main의 70:30 융합 결과를 기준으로
     * JEV를 통한 최종 위험 등급 보정을 수행한다.
     *
     * 융합 점수는 변경하지 않는다.
     */
    public FinalAssessment assess(
            NeuroSymbolicFusionService.FusionResult fusion,
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult,
            boolean phishingUrlMatched,
            Map<String, Object> jevResult) {

        if (fusion == null || ruleResult == null) {
            throw new IllegalArgumentException(
                    "융합 결과와 규칙 기반 결과가 필요합니다.");
        }

        String fusionLevel = normalizeLevel(
                fusion.finalRiskLevel());

        String finalLevel = fusionLevel;
        String decisionReason = "BASE_RISK_MAINTAINED";
        boolean jevUsed = false;

        // 1. 피싱 URL 목록 일치: 위험 등급 우선
        if (phishingUrlMatched) {
            finalLevel = "DANGER";
            decisionReason = "PHISHING_URL_MATCH";

        // 2. RF 분석 실패: 기존 융합 결과 유지
        } else if (mlResult == null) {
            decisionReason = "RF_UNAVAILABLE";

        // 3. JEV 분석 결과가 유효한 경우
        } else {
            String jevLevel = extractJevLevel(jevResult);

            if (jevLevel != null) {

                // SAFE + JEV DANGER -> WARNING
                if ("SAFE".equals(fusionLevel)
                        && "DANGER".equals(jevLevel)) {

                    finalLevel = "WARNING";
                    decisionReason = "JEV_RISK_ESCALATION";
                    jevUsed = true;

                // WARNING + JEV DANGER
                } else if ("WARNING".equals(fusionLevel)
                        && "DANGER".equals(jevLevel)) {

                    boolean strongRiskSignal =
                            ruleResult.suspiciousScore()
                                    >= DANGER_RULE_THRESHOLD
                            || mlResult.maliciousProbability()
                                    >= DANGER_RF_THRESHOLD;

                    if (strongRiskSignal) {
                        finalLevel = "DANGER";
                        decisionReason = "JEV_SUPPORTS_DANGER";
                        jevUsed = true;
                    }
                }
            }
        }

        boolean riskAdjusted =
                !fusionLevel.equals(finalLevel);

        return new FinalAssessment(
                POLICY_VERSION,
                fusionLevel,
                finalLevel,
                riskAdjusted,
                jevUsed,
                decisionReason);
    }

    private String extractJevLevel(
            Map<String, Object> jevResult) {

        if (jevResult == null
                || !"COMPLETED".equals(
                        jevResult.get("status"))) {
            return null;
        }

        Object analysisObject =
                jevResult.get("jevAnalysis");

        if (!(analysisObject instanceof Map<?, ?> analysis)) {
            return null;
        }

        Object levelObject = analysis.get("risk_level");

        if (!(levelObject instanceof String level)) {
            return null;
        }

        return switch (level.trim().toUpperCase(Locale.ROOT)) {
            case "SAFE" -> "SAFE";
            case "CAUTION", "WARNING" -> "WARNING";
            case "DANGER" -> "DANGER";
            default -> null;
        };
    }

    private String normalizeLevel(String level) {

        if (level == null) {
            throw new IllegalArgumentException(
                    "위험 등급이 없습니다.");
        }

        return switch (level.trim().toUpperCase(Locale.ROOT)) {
            case "SAFE" -> "SAFE";
            case "CAUTION", "WARNING" -> "WARNING";
            case "DANGER" -> "DANGER";
            default -> throw new IllegalArgumentException(
                    "지원하지 않는 위험 등급: " + level);
        };
    }

    public record FinalAssessment(
            String policyVersion,
            String fusionRiskLevel,
            String riskLevel,
            boolean riskAdjusted,
            boolean jevUsed,
            String decisionReason) {
    }
}
