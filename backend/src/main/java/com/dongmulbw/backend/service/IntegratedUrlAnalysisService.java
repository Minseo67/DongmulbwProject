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

        /**
         * 규칙 기반 + RF + 조건부 JEV 통합 분석
         */
        public Map<String, Object> analyze(
                        String rawUrl,
                        String normalizedUrl,
                        String domain) {

                // 1. 규칙 기반 및 피싱 블랙리스트 분석
                UrlAnalysisService.AnalysisResult ruleAnalysis = urlAnalysisService.analyze(
                                rawUrl,
                                normalizedUrl,
                                domain);

                double ruleScore = ruleAnalysis.ruleResult().suspiciousScore();

                MlAnalysisService.MlResult mlResult;

                // 2. RF 분석
                try {

                        mlResult = mlAnalysisService.analyze(rawUrl);

                } catch (OrtException | IllegalStateException e) {

                        // RF 분석 실패 시 기존 부분 분석 정책 유지
                        // 블랙리스트 일치: DANGER
                        // 블랙리스트 불일치: CAUTION

                        // RF 분석 실패 시 부분 분석 결과
                        FinalRiskAssessmentService.FinalAssessment assessment = finalRiskAssessmentService.assess(
                                        ruleAnalysis.ruleResult(),
                                        null,
                                        ruleAnalysis.phishingUrlMatched(),
                                        null);

                        // 부분 분석에 대한 자연어 설명 생성
                        RiskExplanationService.RiskExplanation explanation = riskExplanationService.generate(
                                        assessment,
                                        ruleAnalysis.ruleResult(),
                                        null,
                                        null);

                        Map<String, Object> result = new LinkedHashMap<>();

                        result.put("status", "PARTIAL_SUCCESS");
                        result.put("ruleAnalysis", ruleAnalysis);
                        result.put("mlAnalysis", null);

                        // RF 실패 시 JEV 미실행
                        result.put("jevTriggered", false);
                        result.put("jevStatus", "NOT_EVALUATED");
                        result.put("jevSkipReason", "RF_UNAVAILABLE");
                        result.put("jevAnalysis", null);
                        result.put("jevElapsedMs", null);

                        result.put("finalAssessment", assessment);
                        result.put("riskExplanation", explanation);

                        return result;
                }

                // 3. JEV 실행 여부 결정
                Map<String, Object> jevResult;

                if (ruleAnalysis.phishingUrlMatched()) {

                        // 피싱 블랙리스트 일치 시
                        // JEV 조건 검사와 외부 API 호출 모두 생략

                        jevResult = new LinkedHashMap<>();

                        jevResult.put("jevTriggered", false);
                        jevResult.put("status", "SKIPPED");
                        jevResult.put(
                                        "skipReason",
                                        "PHISHING_URL_MATCH");
                        jevResult.put("jevAnalysis", null);
                        jevResult.put("elapsedMs", null);

                } else {

                        // 블랙리스트 불일치 시
                        // 기존 점수 기반 조건 A 또는 B 적용

                        jevResult = jevConditionalAnalysisService.analyze(
                                        normalizedUrl,
                                        ruleScore,
                                        mlResult.maliciousProbability());
                }

                // 4. 최종 위험 등급 판단
                FinalRiskAssessmentService.FinalAssessment assessment = finalRiskAssessmentService.assess(
                                ruleAnalysis.ruleResult(),
                                mlResult,
                                ruleAnalysis.phishingUrlMatched(),
                                jevResult);

                // 5. 사용자 설명 생성
                RiskExplanationService.RiskExplanation explanation = riskExplanationService.generate(
                                assessment,
                                ruleAnalysis.ruleResult(),
                                mlResult,
                                jevResult);

                // 6. 통합 결과 생성
                Map<String, Object> result = new LinkedHashMap<>();

                result.put("status", "SUCCESS");

                result.put("ruleAnalysis", ruleAnalysis);
                result.put("mlAnalysis", mlResult);

                result.put(
                                "jevTriggered",
                                jevResult.get("jevTriggered"));

                result.put(
                                "jevStatus",
                                jevResult.get("status"));

                result.put(
                                "jevSkipReason",
                                jevResult.get("skipReason"));

                result.put(
                                "jevAnalysis",
                                jevResult.get("jevAnalysis"));

                result.put(
                                "jevElapsedMs",
                                jevResult.get("elapsedMs"));

                result.put("finalAssessment", assessment);
                result.put("riskExplanation", explanation);

                return result;
        }
}
