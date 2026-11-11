
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Service
public class FinalRiskAssessmentService {

    private static final String POLICY_VERSION = "priority-v1";

    // 최종 위험도 통합을 위한 임시 RF 구간
    private static final double RF_SAFE_LIMIT = 0.30;
    private static final double RF_DANGER_LIMIT = 0.70;

    private static final Set<String> VALID_LEVELS =
            Set.of("SAFE", "CAUTION", "DANGER");

    public FinalAssessment assess(
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult,
            boolean phishingUrlMatched,
            Map<String, Object> jevResult) {

        if (ruleResult == null) {
            throw new IllegalArgumentException(
                    "규칙 기반 분석 결과가 없습니다.");
        }

        String ruleLevel = normalizeLevel(
                ruleResult.riskLevel());

        // 1. 피싱 URL 목록 일치 여부 우선 확인
        if (phishingUrlMatched) {
            return new FinalAssessment(
                    "DANGER",
                    mlResult == null ? "PARTIAL" : "COMPLETE",
                    "PHISHING_URL_MATCH",
                    false,
                    POLICY_VERSION
            );
        }

        // 2. RF 결과가 없으면 부분 분석으로 처리
        if (mlResult == null) {
            return new FinalAssessment(
                    "CAUTION",
                    "PARTIAL",
                    "RF_UNAVAILABLE",
                    false,
                    POLICY_VERSION
            );
        }

        // 3. RF 확률 검증
        double rfProbability = mlResult.maliciousProbability();

        if (!Double.isFinite(rfProbability)
                || rfProbability < 0.0
                || rfProbability > 1.0) {
            throw new IllegalArgumentException(
                    "RF 확률값이 올바르지 않습니다.");
        }

        // 4. RF 확률을 3단계 등급으로 변환
        String rfLevel = classifyRf(rfProbability);

        // 5. JEV 결과 확인
        String jevLevel = null;
        boolean jevUsed = false;

        if (jevResult != null
                && "COMPLETED".equals(jevResult.get("status"))) {

            Object analysisObject = jevResult.get("jevAnalysis");

            if (analysisObject instanceof Map<?, ?> analysis) {
                Object riskLevel = analysis.get("risk_level");

                if (riskLevel instanceof String level) {
                    String normalizedJevLevel =
                            level.toUpperCase(Locale.ROOT);

                    if (VALID_LEVELS.contains(normalizedJevLevel)) {
                        jevLevel = normalizedJevLevel;
                    }
                }
            }
        }

        // 6. 규칙 기반과 RF 판단이 일치하는 경우
        if (ruleLevel.equals(rfLevel)) {
            return new FinalAssessment(
                    ruleLevel,
                    "COMPLETE",
                    "RULE_RF_AGREEMENT",
                    false,
                    POLICY_VERSION
            );
        }

        // 7. 두 분석이 불일치하고 JEV가 위험을 지지하는 경우
        if ("DANGER".equals(jevLevel)
                && ("DANGER".equals(ruleLevel)
                || "DANGER".equals(rfLevel))) {

            jevUsed = true;

            return new FinalAssessment(
                    "DANGER",
                    "COMPLETE",
                    "JEV_SUPPORTS_DANGER",
                    jevUsed,
                    POLICY_VERSION
            );
        }

        // 8. 그 외 불일치 상황은 주의 등급
        // JEV가 유효한 결과를 제공했다면 보조 근거로 기록
        jevUsed = jevLevel != null;

        return new FinalAssessment(
                "CAUTION",
                "COMPLETE",
                "RULE_RF_CONFLICT",
                jevUsed,
                POLICY_VERSION
        );
    }

    private String classifyRf(double probability) {

        if (probability < RF_SAFE_LIMIT) {
            return "SAFE";
        }

        if (probability < RF_DANGER_LIMIT) {
            return "CAUTION";
        }

        return "DANGER";
    }

    private String normalizeLevel(String level) {

        if (level == null) {
            throw new IllegalArgumentException(
                    "규칙 기반 위험 등급이 없습니다.");
        }

        String normalized =
                level.toUpperCase(Locale.ROOT);

        if (!VALID_LEVELS.contains(normalized)) {
            throw new IllegalArgumentException(
                    "지원하지 않는 규칙 기반 위험 등급: " + level);
        }

        return normalized;
    }

    public record FinalAssessment(
            String riskLevel,
            String assessmentStatus,
            String decisionReason,
            boolean jevUsed,
            String policyVersion) {
    }
}
