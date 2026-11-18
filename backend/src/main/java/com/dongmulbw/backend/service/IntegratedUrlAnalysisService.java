
package com.dongmulbw.backend.service;

import ai.onnxruntime.OrtException;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class IntegratedUrlAnalysisService {

    private final UrlAnalysisService urlAnalysisService;
    private final MlAnalysisService mlAnalysisService;
    private final JevConditionalAnalysisService jevConditionalAnalysisService;
    private final FinalRiskAssessmentService finalRiskAssessmentService;
    private final RiskExplanationService riskExplanationService;

    // 기존 테스트 생성자와의 호환성을 위해
    // 별도 생성자 주입 대신 사용
    private final NeuroSymbolicFusionService fusionService =
            new NeuroSymbolicFusionService();

    public IntegratedUrlAnalysisService(
            UrlAnalysisService urlAnalysisService,
            MlAnalysisService mlAnalysisService,
            JevConditionalAnalysisService jevConditionalAnalysisService,
            FinalRiskAssessmentService finalRiskAssessmentService,
            RiskExplanationService riskExplanationService) {

        this.urlAnalysisService = urlAnalysisService;
        this.mlAnalysisService = mlAnalysisService;
        this.jevConditionalAnalysisService =
                jevConditionalAnalysisService;
        this.finalRiskAssessmentService =
                finalRiskAssessmentService;
        this.riskExplanationService =
                riskExplanationService;
    }

    /**
     * 규칙 기반 + RF + 조건부 JEV 통합 분석
     *
     * 1. 규칙 기반 분석
     * 2. RF 분석
     * 3. 70:30 가중치 융합
     * 4. 조건부 JEV 분석
     * 5. 최종 위험 등급 보정
     * 6. 자연어 설명 생성
     *
     * 참고:
     * 최신 main Controller의 병렬 분석과는 별개의
     * 기존 통합 서비스 경로이다.
     */
    public Map<String, Object> analyze(
            String rawUrl,
            String normalizedUrl,
            String domain) {

        // 1. 규칙 기반 및 피싱 블랙리스트 분석
        UrlAnalysisService.AnalysisResult ruleAnalysis =
                urlAnalysisService.analyze(
                        rawUrl,
                        normalizedUrl,
                        domain
                );

        double ruleScore =
                ruleAnalysis.ruleResult().suspiciousScore();

        MlAnalysisService.MlResult mlResult;

        // 2. RF 분석
        try {

            mlResult = mlAnalysisService.analyze(rawUrl);

        } catch (OrtException | IllegalStateException e) {

            // RF 분석 실패 시 기존 부분 분석 흐름 유지
            // 실제 RF 예측값은 존재하지 않는다.
            //
            // 이 경우 융합 점수는 규칙 점수를 사용하고
            // RF가 없다는 사실은 별도 상태로 표시한다.

            String fallbackLevel =
                    normalizeRuleLevel(
                            ruleAnalysis.ruleResult().riskLevel()
                    );

            if (ruleAnalysis.phishingUrlMatched()) {
                fallbackLevel = "DANGER";
            }

            NeuroSymbolicFusionService.FusionResult fusion =
                    new NeuroSymbolicFusionService.FusionResult(
                            ruleScore,
                            Double.NaN,
                            ruleScore,
                            fallbackLevel
                    );

            FinalRiskAssessmentService.FinalAssessment assessment =
                    finalRiskAssessmentService.assess(
                            fusion,
                            ruleAnalysis.ruleResult(),
                            null,
                            ruleAnalysis.phishingUrlMatched(),
                            null
                    );

            RiskExplanationService.RiskExplanation explanation =
                    riskExplanationService.generate(
                            assessment,
                            ruleAnalysis.ruleResult(),
                            null,
                            null
                    );

            Map<String, Object> result =
                    new LinkedHashMap<>();

            result.put("status", "PARTIAL_SUCCESS");
            result.put("ruleAnalysis", ruleAnalysis);
            result.put("mlAnalysis", null);

            result.put("fusionAnalysis", fusion);
            result.put("finalScore", fusion.finalScore());
            result.put(
                    "finalRiskLevel",
                    assessment.riskLevel()
            );

            result.put("jevTriggered", false);
            result.put("jevStatus", "NOT_EVALUATED");
            result.put(
                    "jevSkipReason",
                    "RF_UNAVAILABLE"
            );
            result.put("jevAnalysis", null);
            result.put("jevElapsedMs", null);

            result.put("finalAssessment", assessment);
            result.put("riskExplanation", explanation);

            return result;
        }

        // 3. 규칙 기반 70% + RF 30% 가중치 융합
        NeuroSymbolicFusionService.FusionResult fusion =
                fusionService.fuse(
                        ruleAnalysis.ruleResult(),
                        mlResult
                );

        // 4. 조건부 JEV 실행
        Map<String, Object> jevResult;

        if (ruleAnalysis.phishingUrlMatched()) {

            // 피싱 블랙리스트 일치 시
            // JEV 실행 조건 검사 및 API 호출 생략

            jevResult = new LinkedHashMap<>();

            jevResult.put("jevTriggered", false);
            jevResult.put("status", "SKIPPED");
            jevResult.put(
                    "skipReason",
                    "PHISHING_URL_MATCH"
            );
            jevResult.put("jevAnalysis", null);
            jevResult.put("elapsedMs", null);

        } else {

            // 기존 조건부 JEV 정책 유지
            // 조건 A: 규칙 점수와 RF 점수 차이 >= 40
            // 조건 B: 두 점수 평균 40~60

            jevResult =
                    jevConditionalAnalysisService.analyze(
                            normalizedUrl,
                            ruleScore,
                            mlResult.maliciousProbability()
                    );
        }

        // 5. 최종 위험 등급 보정
        // 70:30 점수는 그대로 유지
        FinalRiskAssessmentService.FinalAssessment assessment =
                finalRiskAssessmentService.assess(
                        fusion,
                        ruleAnalysis.ruleResult(),
                        mlResult,
                        ruleAnalysis.phishingUrlMatched(),
                        jevResult
                );

        // 6. 사용자 자연어 설명 생성
        RiskExplanationService.RiskExplanation explanation =
                riskExplanationService.generate(
                        assessment,
                        ruleAnalysis.ruleResult(),
                        mlResult,
                        jevResult
                );

        // 7. 최종 응답 생성
        Map<String, Object> result =
                new LinkedHashMap<>();

        result.put("status", "SUCCESS");

        result.put("ruleAnalysis", ruleAnalysis);
        result.put("mlAnalysis", mlResult);

        result.put("fusionAnalysis", fusion);
        result.put("finalScore", fusion.finalScore());
        result.put(
                "fusionRiskLevel",
                assessment.fusionRiskLevel()
        );
        result.put(
                "finalRiskLevel",
                assessment.riskLevel()
        );
        result.put(
                "riskAdjusted",
                assessment.riskAdjusted()
        );
        result.put(
                "decisionReason",
                assessment.decisionReason()
        );

        result.put(
                "jevTriggered",
                jevResult.get("jevTriggered")
        );
        result.put(
                "jevStatus",
                jevResult.get("status")
        );
        result.put(
                "jevSkipReason",
                jevResult.get("skipReason")
        );
        result.put(
                "jevAnalysis",
                jevResult.get("jevAnalysis")
        );
        result.put(
                "jevElapsedMs",
                jevResult.get("elapsedMs")
        );

        result.put("finalAssessment", assessment);
        result.put("riskExplanation", explanation);

        return result;
    }

    /**
     * 기존 규칙 기반 위험 등급을
     * 최신 main의 등급 체계로 변환한다.
     */
    private String normalizeRuleLevel(String level) {

        if (level == null) {
            return "WARNING";
        }

        return switch (level.trim().toUpperCase(
                java.util.Locale.ROOT)) {

            case "SAFE" -> "SAFE";
            case "CAUTION", "WARNING" -> "WARNING";
            case "DANGER" -> "DANGER";
            default -> "WARNING";
        };
    }
}
