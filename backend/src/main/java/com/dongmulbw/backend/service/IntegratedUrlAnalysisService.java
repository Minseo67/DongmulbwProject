
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

    public IntegratedUrlAnalysisService(
            UrlAnalysisService urlAnalysisService,
            MlAnalysisService mlAnalysisService,
            JevConditionalAnalysisService jevConditionalAnalysisService,
            FinalRiskAssessmentService finalRiskAssessmentService,
            RiskExplanationService riskExplanationService) {

        this.urlAnalysisService = urlAnalysisService;
        this.mlAnalysisService = mlAnalysisService;
        this.jevConditionalAnalysisService = jevConditionalAnalysisService;
        this.finalRiskAssessmentService = finalRiskAssessmentService;
        this.riskExplanationService = riskExplanationService;
    }

    public Map<String, Object> analyze(
            String rawUrl,
            String normalizedUrl,
            String domain) {

        // 1. 규칙 기반 분석
        UrlAnalysisService.AnalysisResult ruleAnalysis =
                urlAnalysisService.analyze(
                        rawUrl,
                        normalizedUrl,
                        domain
                );

        double ruleScore =
                ruleAnalysis.ruleResult().suspiciousScore();

        // 2. RF 모델 분석
        MlAnalysisService.MlResult mlResult;

        try {
            mlResult = mlAnalysisService.analyze(rawUrl);

        } catch (OrtException | IllegalStateException e) {

            // RF 분석 실패 시 부분 분석 결과
            FinalRiskAssessmentService.FinalAssessment finalAssessment =
                    finalRiskAssessmentService.assess(
                            ruleAnalysis.ruleResult(),
                            null,
                            ruleAnalysis.phishingUrlMatched(),
                            null
                    );

            // 부분 분석에 대한 자연어 설명 생성
            RiskExplanationService.RiskExplanation riskExplanation =
                    riskExplanationService.generate(
                            finalAssessment,
                            ruleAnalysis.ruleResult(),
                            null,
                            null
                    );

            Map<String, Object> result = new LinkedHashMap<>();

            result.put("status", "PARTIAL_SUCCESS");
            result.put("ruleAnalysis", ruleAnalysis);
            result.put("mlAnalysis", null);

            result.put("jevTriggered", false);
            result.put("jevStatus", "NOT_EVALUATED");
            result.put("jevAnalysis", null);
            result.put("jevElapsedMs", null);

            result.put("finalAssessment", finalAssessment);
            result.put("riskExplanation", riskExplanation);

            return result;
        }

        // 3. JEV 조건부 분석
        double rfProbability =
                mlResult.maliciousProbability();

        Map<String, Object> jevResult =
                jevConditionalAnalysisService.analyze(
                        normalizedUrl,
                        ruleScore,
                        rfProbability
                );

        // 4. 최종 위험 등급 판단
        FinalRiskAssessmentService.FinalAssessment finalAssessment =
                finalRiskAssessmentService.assess(
                        ruleAnalysis.ruleResult(),
                        mlResult,
                        ruleAnalysis.phishingUrlMatched(),
                        jevResult
                );

        // 5. 자연어 설명 생성
        RiskExplanationService.RiskExplanation riskExplanation =
                riskExplanationService.generate(
                        finalAssessment,
                        ruleAnalysis.ruleResult(),
                        mlResult,
                        jevResult
                );

        // 6. 최종 통합 결과 반환
        Map<String, Object> result = new LinkedHashMap<>();

        result.put("status", "SUCCESS");

        result.put("ruleAnalysis", ruleAnalysis);
        result.put("mlAnalysis", mlResult);

        result.put("jevTriggered", jevResult.get("jevTriggered"));
        result.put("jevStatus", jevResult.get("status"));
        result.put("jevAnalysis", jevResult.get("jevAnalysis"));
        result.put("jevElapsedMs", jevResult.get("elapsedMs"));

        result.put("finalAssessment", finalAssessment);
        result.put("riskExplanation", riskExplanation);

        return result;
    }
}
