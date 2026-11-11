
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class RiskExplanationService {

    public RiskExplanation generate(
            FinalRiskAssessmentService.FinalAssessment finalAssessment,
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult,
            Map<String, Object> jevResult) {

        if (finalAssessment == null) {
            throw new IllegalArgumentException(
                    "최종 위험 등급 결과가 없습니다.");
        }

        if (ruleResult == null) {
            throw new IllegalArgumentException(
                    "규칙 기반 분석 결과가 없습니다.");
        }

        String riskLevel = finalAssessment.riskLevel();
        String decisionReason = finalAssessment.decisionReason();

        String title = createTitle(riskLevel);
        String description;

        switch (decisionReason) {

            case "PHISHING_URL_MATCH":
                description =
                        "해당 URL이 수집된 피싱 URL 목록과 일치하여 "
                        + "위험 등급으로 분류되었습니다. "
                        + "개인정보 입력이나 파일 다운로드에 주의하세요.";
                break;

            case "RULE_RF_AGREEMENT":
                description = createAgreementDescription(
                        riskLevel, ruleResult, mlResult);
                break;

            case "JEV_SUPPORTS_DANGER":
                description =
                        "규칙 기반 분석 또는 AI 모델에서 높은 위험 가능성이 "
                        + "확인되었으며, 추가 AI 분석에서도 위험한 URL로 "
                        + "판단되어 위험 등급으로 분류되었습니다.";
                break;

            case "RULE_RF_CONFLICT":
                description = createConflictDescription(
                        ruleResult, mlResult, jevResult);
                break;

            case "RF_UNAVAILABLE":
                description =
                        "AI 모델 분석을 완료하지 못해 일부 분석 결과만 "
                        + "확인되었습니다. 충분한 판단 근거가 확보되지 않아 "
                        + "주의 등급으로 표시했습니다.";
                break;

            default:
                description =
                        "URL 분석 결과를 바탕으로 위험 등급을 결정했습니다. "
                        + "분석 결과를 확인하고 주의하여 이용하세요.";
        }

        return new RiskExplanation(
                title,
                description
        );
    }

    private String createTitle(String riskLevel) {

        return switch (riskLevel) {
            case "SAFE" -> "뚜렷한 위험 징후가 발견되지 않았습니다.";
            case "CAUTION" -> "주의가 필요한 URL입니다.";
            case "DANGER" -> "위험 가능성이 높은 URL입니다.";
            default -> "URL 분석 결과를 확인해 주세요.";
        };
    }

    private String createAgreementDescription(
            String riskLevel,
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult) {

        return switch (riskLevel) {

            case "SAFE" ->
                    "규칙 기반 분석과 AI 모델에서 모두 낮은 위험 가능성이 "
                    + "나타났습니다. 다만 분석 결과가 사이트의 안전성을 "
                    + "완전히 보장하는 것은 아닙니다.";

            case "CAUTION" ->
                    "규칙 기반 분석과 AI 모델에서 모두 주의가 필요한 "
                    + "수준의 위험 신호가 나타나 주의 등급으로 "
                    + "분류되었습니다.";

            case "DANGER" ->
                    "규칙 기반 분석과 AI 모델에서 모두 높은 위험 "
                    + "가능성이 나타나 위험 등급으로 분류되었습니다.";

            default ->
                    "규칙 기반 분석과 AI 모델의 결과를 종합하여 "
                    + "위험 등급을 결정했습니다.";
        };
    }

    private String createConflictDescription(
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult,
            Map<String, Object> jevResult) {

        StringBuilder description = new StringBuilder();

        description.append(
                "규칙 기반 분석과 AI 모델의 위험 판단이 서로 다르게 "
                + "나타났습니다. ");

        if ("SAFE".equalsIgnoreCase(ruleResult.riskLevel())) {
            description.append(
                    "규칙 기반 분석에서는 뚜렷한 위험 징후가 "
                    + "발견되지 않았습니다. ");
        }

        if (mlResult != null
                && mlResult.maliciousProbability() >= 0.70f) {
            description.append(
                    "AI 모델에서는 높은 악성 가능성이 예측되었습니다. ");
        }

        String jevLevel = extractJevLevel(jevResult);

        if ("safe".equals(jevLevel)) {
            description.append(
                    "추가 AI 분석에서는 안전한 것으로 판단되었습니다. ");
        } else if ("caution".equals(jevLevel)) {
            description.append(
                    "추가 AI 분석에서도 주의가 필요한 것으로 "
                    + "판단되었습니다. ");
        } else if ("danger".equals(jevLevel)) {
            description.append(
                    "추가 AI 분석에서는 위험한 것으로 판단되었습니다. ");
        } else if ("unknown".equals(jevLevel)) {
            description.append(
                    "추가 AI 분석에서 위험 여부를 명확히 "
                    + "판단하지 못했습니다. ");
        }

        description.append(
                "분석 결과가 일치하지 않아 주의 등급으로 분류되었습니다.");

        return description.toString();
    }

    private String extractJevLevel(Map<String, Object> jevResult) {

        if (jevResult == null
                || !"COMPLETED".equals(jevResult.get("status"))) {
            return null;
        }

        Object analysisObject = jevResult.get("jevAnalysis");

        if (!(analysisObject instanceof Map<?, ?> analysis)) {
            return null;
        }

        Object level = analysis.get("risk_level");

        if (level instanceof String riskLevel) {
            return riskLevel.toLowerCase(java.util.Locale.ROOT);
        }

        return null;
    }

    public record RiskExplanation(
            String title,
            String description) {
    }
}
