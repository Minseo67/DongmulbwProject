
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;

@Service
public class RiskExplanationService {

    public RiskExplanation generate(
            FinalRiskAssessmentService.FinalAssessment assessment,
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult,
            Map<String, Object> jevResult) {

        if (assessment == null || ruleResult == null) {
            throw new IllegalArgumentException(
                    "최종 판단 결과와 규칙 기반 분석 결과가 필요합니다.");
        }

        String level = assessment.riskLevel();
        String reason = assessment.decisionReason();

        String description;

        switch (reason) {

            case "PHISHING_URL_MATCH" ->
                    description =
                            "해당 URL이 수집된 피싱 URL 목록과 일치했습니다. "
                            + "피싱 목록 일치 결과를 우선 적용하여 "
                            + "최종 위험 등급으로 분류했습니다. "
                            + "개인정보 입력이나 파일 다운로드를 피하세요.";

            case "RF_UNAVAILABLE" ->
                    description =
                            "RF 모델 분석을 완료하지 못했습니다. "
                            + "규칙 기반 분석 결과를 바탕으로 "
                            + "위험 수준을 표시했습니다. "
                            + "JEV 보조 분석은 수행하지 않았습니다.";

            case "JEV_RISK_ESCALATION" ->
                    description =
                            "규칙 기반과 RF의 가중 분석에서는 "
                            + "낮은 위험 수준으로 판단했으나, "
                            + "추가 JEV 분석에서 높은 위험 가능성이 "
                            + "확인되어 최종 등급을 주의로 상향했습니다. "
                            + "기존 가중 점수는 변경하지 않았습니다.";

            case "JEV_SUPPORTS_DANGER" ->
                    description =
                            "규칙 기반과 RF의 가중 분석에서는 "
                            + "주의 수준으로 판단했습니다. "
                            + "그러나 규칙 기반 또는 RF에서 높은 위험 신호가 "
                            + "나타났으며, JEV 분석에서도 위험 가능성이 "
                            + "높게 판단되어 최종 등급을 위험으로 상향했습니다. "
                            + "기존 가중 점수는 변경하지 않았습니다.";

            default ->
                    description =
                            baseDescription(level)
                            + jevDescription(jevResult)
                            + "최종 위험 등급은 규칙 기반 70%, "
                            + "RF 30%의 가중 분석 결과를 기준으로 "
                            + "결정했습니다.";
        }

        return new RiskExplanation(
                title(level),
                description);
    }

    private String title(String level) {

        return switch (level) {
            case "SAFE" ->
                    "뚜렷한 위험 징후가 발견되지 않았습니다.";
            case "WARNING" ->
                    "주의가 필요한 URL입니다.";
            case "DANGER" ->
                    "위험 가능성이 높은 URL입니다.";
            default ->
                    "URL 분석 결과를 확인해 주세요.";
        };
    }

    private String baseDescription(String level) {

        return switch (level) {
            case "SAFE" ->
                    "규칙 기반과 RF의 가중 분석에서 "
                    + "낮은 위험 수준으로 판단했습니다. "
                    + "다만 사이트의 안전성을 완전히 보장하지는 않습니다. ";

            case "WARNING" ->
                    "규칙 기반과 RF의 가중 분석에서 "
                    + "주의가 필요한 수준으로 판단했습니다. ";

            case "DANGER" ->
                    "규칙 기반과 RF의 가중 분석에서 "
                    + "높은 위험 가능성이 나타났습니다. "
                    + "개인정보 입력이나 파일 다운로드에 주의하세요. ";

            default -> "";
        };
    }

    private String jevDescription(Map<String, Object> jevResult) {

        if (jevResult == null) {
            return "JEV 보조 분석 결과는 제공되지 않았습니다. ";
        }

        Object statusObject = jevResult.get("status");

        if (!(statusObject instanceof String status)) {
            return "JEV 보조 분석 상태를 확인할 수 없습니다. ";
        }

        switch (status.toUpperCase(Locale.ROOT)) {

            case "SKIPPED":
                return "JEV 실행 조건을 충족하지 않아 "
                        + "추가 분석을 생략했습니다. ";

            case "UNAVAILABLE":
            case "FAILED":
            case "ERROR":
                return "JEV 보조 분석을 시도했지만 "
                        + "유효한 결과를 얻지 못했습니다. ";

            case "COMPLETED":
                Object analysisObject =
                        jevResult.get("jevAnalysis");

                if (analysisObject instanceof Map<?, ?> analysis) {

                    Object levelObject = analysis.get("risk_level");

                    if (levelObject instanceof String jevLevel) {

                        return switch (
                                jevLevel.toLowerCase(Locale.ROOT)) {

                            case "safe" ->
                                    "JEV는 낮은 위험 가능성을 나타냈습니다. ";

                            case "caution", "warning" ->
                                    "JEV는 주의가 필요한 수준으로 판단했습니다. ";

                            case "danger" ->
                                    "JEV는 높은 위험 가능성을 나타냈습니다. ";

                            default ->
                                    "JEV 결과의 위험 등급을 확인할 수 없습니다. ";
                        };
                    }
                }

                return "JEV 분석은 완료되었지만 "
                        + "유효한 위험 등급을 확인하지 못했습니다. ";

            default:
                return "JEV 보조 분석 상태를 확인할 수 없습니다. ";
        }
    }

    public record RiskExplanation(
            String title,
            String description) {
    }
}
