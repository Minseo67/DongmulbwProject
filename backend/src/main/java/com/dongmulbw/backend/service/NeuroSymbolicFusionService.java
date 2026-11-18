
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

@Service
public class NeuroSymbolicFusionService {

    private static final double RULE_WEIGHT = 0.7;
    private static final double RF_WEIGHT = 0.3;

    private static final double WARNING_THRESHOLD = 30.0;
    private static final double DANGER_THRESHOLD = 60.0;

    public FusionResult fuse(
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult rfResult) {

        if (ruleResult == null || rfResult == null) {
            throw new IllegalArgumentException(
                    "Analysis results must not be null");
        }

        double ruleScore = ruleResult.suspiciousScore();
        double rfProbability = rfResult.maliciousProbability();

        validateRuleScore(ruleScore);
        validateRfProbability(rfProbability);

        double finalScore = ruleScore * RULE_WEIGHT
                + rfProbability * 100.0 * RF_WEIGHT;

        return new FusionResult(
                ruleScore,
                rfProbability,
                finalScore,
                determineRiskLevel(finalScore));
    }

    public FusionResult fuse(
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult rfResult,
            DomainReputationService.ReputationStatus reputationStatus) {

        // 블랙리스트 규칙 점수는 UrlAnalysisService에서
        // 100점으로 보정한 상태로 전달된다.
        // 평판에 따른 최종 점수 강제 변경은 하지 않는다.
        return fuse(ruleResult, rfResult);
    }

    private void validateRuleScore(double score) {
        if (!Double.isFinite(score)
                || score < 0.0
                || score > 100.0) {
            throw new IllegalArgumentException(
                    "Invalid rule score");
        }
    }

    private void validateRfProbability(double probability) {
        if (!Double.isFinite(probability)
                || probability < 0.0
                || probability > 1.0) {
            throw new IllegalArgumentException(
                    "Invalid RF probability");
        }
    }

    private String determineRiskLevel(double score) {
        if (score >= DANGER_THRESHOLD) {
            return "DANGER";
        }
        if (score >= WARNING_THRESHOLD) {
            return "WARNING";
        }
        return "SAFE";
    }

    // DB 도메인 평판을 최종 판정에 반영한다.
    // 블랙리스트는 최종 DANGER로 고정하고,
    // 화이트리스트는 UrlAnalysisService에서 적용한 10점 감점을 유지한다.
    public FusionResult fuse(
            RuleAnalysisResult ruleResult,
            MlAnalysisService.MlResult rfResult,
            DomainReputationService.ReputationStatus reputationStatus) {

        FusionResult weighted = fuse(ruleResult, rfResult);
        if (reputationStatus == DomainReputationService.ReputationStatus.BLACKLISTED) {
            return new FusionResult(
                    weighted.ruleScore(),
                    weighted.rfProbability(),
                    weighted.finalScore(),
                    "DANGER"
            );
        }
        return weighted;
    }

    public record FusionResult(
            double ruleScore,
            double rfProbability,
            double finalScore,
            String finalRiskLevel) {
    }
}
