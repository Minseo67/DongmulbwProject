
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

@Service
public class NeuroSymbolicFusionService {

    // 1차 결합 가중치
    private static final double RULE_WEIGHT = 0.7;
    private static final double RF_WEIGHT = 0.3;

    // 최종 위험 등급 경계값
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

        // 입력값 검증
        if (!Double.isFinite(ruleScore)
                || ruleScore < 0.0
                || ruleScore > 100.0) {
            throw new IllegalArgumentException(
                    "Invalid rule score");
        }

        if (!Double.isFinite(rfProbability)
                || rfProbability < 0.0
                || rfProbability > 1.0) {
            throw new IllegalArgumentException(
                    "Invalid RF probability");
        }

        // 규칙 점수 70% + RF 확률 30%
        double finalScore =
                (ruleScore * RULE_WEIGHT)
                + (rfProbability * 100.0 * RF_WEIGHT);

        // 최종 위험 등급 판정
        String finalRiskLevel;

        if (finalScore >= DANGER_THRESHOLD) {
            finalRiskLevel = "DANGER";
        } else if (finalScore >= WARNING_THRESHOLD) {
            finalRiskLevel = "WARNING";
        } else {
            finalRiskLevel = "SAFE";
        }

        return new FusionResult(
                ruleScore,
                rfProbability,
                finalScore,
                finalRiskLevel
        );
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
            String finalRiskLevel
    ) {}
}
