
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;

@Service
public class RiskExplanationService {

    /**
     * 최종 위험 등급과 분석 결과를 바탕으로
     * 사용자에게 표시할 설명을 생성합니다.
     */
    public RiskExplanation generate(
            FinalRiskAssessmentService.FinalAssessment assessment,
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult mlResult,
            Map<String, Object> jevResult) {

        // 1. 필수 입력값 검증
        if (assessment == null) {
            throw new IllegalArgumentException(
                    "최종 위험 등급 결과가 없습니다.");
        }

        if (ruleResult == null) {
            throw new IllegalArgumentException(
                    "규칙 기반 분석 결과가 없습니다.");
        }

        String finalLevel = upper(assessment.riskLevel());
        String reason = assessment.decisionReason();

        String description;

        // 2. 최종 판단 사유에 따른 설명 생성
        switch (reason) {

            // 피싱 블랙리스트 일치
            case "PHISHING_URL_MATCH" -> description = "해당 URL이 수집된 피싱 URL 목록과 일치했습니다. "
                    + "이 일치 결과를 우선 적용하여 최종 위험 등급으로 분류했습니다. "
                    + "JEV 보조 분석은 수행하지 않았습니다. "
                    + "개인정보 입력이나 파일 다운로드를 피하는 것이 좋습니다.";

            // RF 분석 실패
            case "RF_UNAVAILABLE" -> description = "AI 모델(RF) 분석을 완료하지 못했습니다. "
                    + ruleDescription(
                            upper(ruleResult.riskLevel()))
                    + " "
                    + "규칙 기반과 RF의 결과를 비교할 수 없어 "
                    + "최종 주의 등급으로 표시했습니다. "
                    + "JEV 보조 분석도 수행하지 않았습니다.";

            // 규칙 기반과 RF 위험 등급 일치
            case "RULE_RF_AGREEMENT" -> description = agreementDescription(finalLevel)
                    + " "
                    + auxiliaryDescription(jevResult, false)
                    + "최종 등급은 규칙 기반과 RF의 "
                    + "일치한 판단을 적용했습니다.";

            // JEV가 높은 위험 판단을 뒷받침한 경우
            case "JEV_SUPPORTS_DANGER" -> description = "규칙 기반과 RF의 판단이 서로 다르게 나타났습니다. "
                    + conflictDetail(
                            upper(ruleResult.riskLevel()),
                            rfLevel(mlResult))
                    + " "
                    + "추가 AI 분석(JEV)에서도 위험한 것으로 판단했습니다. "
                    + "규칙 기반 또는 RF에서 나타난 높은 위험 가능성을 "
                    + "JEV가 뒷받침하여 "
                    + "최종 위험 등급으로 분류했습니다.";

            // 규칙 기반과 RF 판단 불일치
            case "RULE_RF_CONFLICT" -> description = "규칙 기반과 RF의 위험 판단이 "
                    + "서로 다르게 나타났습니다. "
                    + conflictDetail(
                            upper(ruleResult.riskLevel()),
                            rfLevel(mlResult))
                    + " "
                    + auxiliaryDescription(jevResult, true)
                    + "현재 통합 판단 기준에서는 두 분석이 불일치하고 "
                    + "JEV를 통한 위험 확정 조건도 충족하지 않아 "
                    + "최종 주의 등급으로 분류했습니다.";

            // 정의되지 않은 판단 사유
            default -> description = "URL 분석 결과를 종합하여 "
                    + "최종 위험 등급을 결정했습니다. "
                    + "분석 결과만으로 사이트의 안전성을 "
                    + "완전히 보장할 수는 없습니다.";
        }

        // 3. 사용자에게 표시할 제목과 설명 반환
        return new RiskExplanation(
                title(finalLevel),
                description);
    }

    /**
     * 최종 위험 등급별 제목
     */
    private String title(String level) {

        if ("SAFE".equals(level)) {
            return "뚜렷한 위험 징후가 발견되지 않았습니다.";
        }

        if ("CAUTION".equals(level)) {
            return "주의가 필요한 URL입니다.";
        }

        if ("DANGER".equals(level)) {
            return "위험 가능성이 높은 URL입니다.";
        }

        return "URL 분석 결과를 확인해 주세요.";
    }

    /**
     * 규칙 기반과 RF의 위험 등급이 일치한 경우
     */
    private String agreementDescription(String level) {

        if ("SAFE".equals(level)) {
            return "규칙 기반과 RF 모두 "
                    + "낮은 위험 가능성을 나타냈습니다. "
                    + "다만 이 결과가 사이트의 안전성을 "
                    + "완전히 보장하지는 않습니다.";
        }

        if ("CAUTION".equals(level)) {
            return "규칙 기반과 RF 모두 "
                    + "주의가 필요한 수준으로 판단했습니다.";
        }

        if ("DANGER".equals(level)) {
            return "규칙 기반과 RF 모두 "
                    + "높은 위험 가능성을 나타냈습니다. "
                    + "해당 URL 이용과 개인정보 입력에 주의하세요.";
        }

        return "규칙 기반과 RF의 결과를 비교했습니다.";
    }

    /**
     * 규칙 기반과 RF가 서로 다르게 판단한
     * 여섯 가지 조합별 설명
     */
    private String conflictDetail(
            String rule,
            String rf) {

        // 규칙 SAFE / RF CAUTION
        if ("SAFE".equals(rule)
                && "CAUTION".equals(rf)) {

            return "규칙 기반에서는 뚜렷한 위험 징후가 없었으나 "
                    + "RF는 주의 수준으로 예측했습니다.";
        }

        // 규칙 SAFE / RF DANGER
        if ("SAFE".equals(rule)
                && "DANGER".equals(rf)) {

            return "규칙 기반에서는 뚜렷한 위험 징후가 없었으나 "
                    + "RF는 높은 악성 가능성을 예측했습니다.";
        }

        // 규칙 CAUTION / RF SAFE
        if ("CAUTION".equals(rule)
                && "SAFE".equals(rf)) {

            return "규칙 기반에서는 주의 신호가 나타났으나 "
                    + "RF는 낮은 위험 가능성을 예측했습니다.";
        }

        // 규칙 CAUTION / RF DANGER
        if ("CAUTION".equals(rule)
                && "DANGER".equals(rf)) {

            return "규칙 기반에서는 주의 수준으로 판단했으나 "
                    + "RF는 높은 악성 가능성을 예측했습니다.";
        }

        // 규칙 DANGER / RF SAFE
        if ("DANGER".equals(rule)
                && "SAFE".equals(rf)) {

            return "규칙 기반에서는 높은 위험 가능성이 나타났으나 "
                    + "RF는 낮은 위험 가능성을 예측했습니다.";
        }

        // 규칙 DANGER / RF CAUTION
        if ("DANGER".equals(rule)
                && "CAUTION".equals(rf)) {

            return "규칙 기반에서는 높은 위험 가능성이 나타났으나 "
                    + "RF는 주의 수준으로 예측했습니다.";
        }

        return "두 분석에서 서로 다른 위험 수준이 나타났습니다.";
    }

    /**
     * JEV 실행 여부 및 결과에 대한 설명
     *
     * @param jevResult JEV 분석 결과
     * @param conflict  규칙 기반과 RF의 등급 불일치 여부
     */
    private String auxiliaryDescription(
            Map<String, Object> jevResult,
            boolean conflict) {

        // JEV 결과 자체가 없는 경우
        if (jevResult == null) {
            return "JEV 보조 분석 결과는 제공되지 않았습니다. ";
        }

        String status = upper(
                string(jevResult.get("status")));

        // JEV 미실행
        if ("SKIPPED".equals(status)) {

            String skipReason = upper(
                    string(jevResult.get("skipReason")));

            // 피싱 블랙리스트 일치로 생략
            if ("PHISHING_URL_MATCH".equals(skipReason)) {
                return "피싱 URL 목록에 일치하여 "
                        + "JEV 분석을 생략했습니다. ";
            }

            // 점수 조건을 충족하지 않아 생략
            if ("SCORE_CONDITIONS_NOT_MET".equals(skipReason)) {
                return "점수 차이 40점 이상 또는 "
                        + "평균 점수 40~60점이라는 "
                        + "JEV 실행 조건을 충족하지 않아 "
                        + "추가 분석을 생략했습니다. ";
            }

            // 기타 생략
            return "JEV 보조 분석은 실행되지 않았습니다. ";
        }

        // JEV 분석 실패
        if ("UNAVAILABLE".equals(status)
                || "FAILED".equals(status)
                || "ERROR".equals(status)) {

            return "JEV 보조 분석을 시도했지만 "
                    + "유효한 결과를 얻지 못했습니다. ";
        }

        // 완료 상태가 아닌 경우
        if (!"COMPLETED".equals(status)) {
            return "JEV 보조 분석의 유효한 결과를 "
                    + "확인할 수 없었습니다. ";
        }

        // JEV 분석 완료: 위험 등급 확인
        String level = jevLevel(jevResult);

        String detail;

        if ("SAFE".equals(level)) {

            detail = "JEV는 낮은 위험 가능성을 나타냈습니다. ";

        } else if ("CAUTION".equals(level)) {

            detail = "JEV는 주의가 필요한 수준으로 판단했습니다. ";

        } else if ("DANGER".equals(level)) {

            detail = "JEV는 높은 위험 가능성을 나타냈습니다. ";

        } else {

            detail = "JEV 분석은 완료되었지만 "
                    + "유효한 위험 등급을 확인하지 못했습니다. ";
        }

        // 규칙 기반과 RF의 판단이 일치한 경우
        if (!conflict) {

            return detail
                    + "JEV 결과와 관계없이 "
                    + "규칙 기반과 RF의 일치한 판단을 "
                    + "우선 적용했습니다. ";
        }

        // 규칙·RF 불일치 + JEV DANGER
        // 이 분기는 최종 판단이 RULE_RF_CONFLICT인 경우에 사용
        if ("DANGER".equals(level)) {

            return detail
                    + "단, 규칙 기반과 RF 모두 위험 등급이 아니어서 "
                    + "JEV만으로 최종 위험 등급을 "
                    + "확정하지 않았습니다. ";
        }

        return detail;
    }

    /**
     * JEV 응답에서 risk_level 추출
     */
    private String jevLevel(
            Map<String, Object> jevResult) {

        Object analysisObject = jevResult.get("jevAnalysis");

        if (!(analysisObject instanceof Map<?, ?> analysis)) {
            return null;
        }

        return upper(
                string(analysis.get("risk_level")));
    }

    /**
     * 규칙 기반 등급별 설명
     */
    private String ruleDescription(String level) {

        if ("SAFE".equals(level)) {
            return "규칙 기반에서는 뚜렷한 위험 징후가 "
                    + "발견되지 않았습니다.";
        }

        if ("CAUTION".equals(level)) {
            return "규칙 기반에서는 주의가 필요한 "
                    + "위험 신호가 나타났습니다.";
        }

        if ("DANGER".equals(level)) {
            return "규칙 기반에서는 높은 위험 가능성이 "
                    + "나타났습니다.";
        }

        return "규칙 기반 결과는 확인되었습니다.";
    }

    /**
     * RF 악성 확률을 위험 등급으로 변환
     *
     * 기존 FinalRiskAssessmentService 기준 유지
     * SAFE: 0.30 미만
     * CAUTION: 0.30 이상 ~ 0.70 미만
     * DANGER: 0.70 이상
     */
    private String rfLevel(
            MlAnalysisService.MlResult ml) {

        if (ml == null) {
            return null;
        }

        double p = ml.maliciousProbability();

        if (!Double.isFinite(p)
                || p < 0
                || p > 1) {
            return null;
        }

        if (p < 0.30) {
            return "SAFE";
        }

        if (p < 0.70) {
            return "CAUTION";
        }

        return "DANGER";
    }

    /**
     * Object를 문자열로 변환
     */
    private String string(Object value) {
        return value instanceof String s ? s : null;
    }

    /**
     * 문자열을 대문자로 정규화
     */
    private String upper(String value) {

        return value == null
                ? null
                : value.trim().toUpperCase(Locale.ROOT);
    }

    /**
     * 사용자에게 반환할 설명 데이터
     */
    public record RiskExplanation(
            String title,
            String description) {
    }
}
