package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.entity.UrlAnalysis;
import com.dongmulbw.backend.service.*;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.HashMap;

@RestController
@RequestMapping("/api/urls")
public class UrlAnalysisController {

        private static final int LEASE_SECONDS = 300;
        private static final int CACHE_HOURS = 24;

        private final UrlNormalizationService normalizationService;
        private final UrlRegistrationService registrationService;
        private final JevAnalysisService jevAnalysisService;
        private final AnalysisVersionService versionService;
        private final UrlAnalysisCacheService cacheService;
        private final ParallelUrlAnalysisService parallelService;
        private final AnalysisRunExecutionService runExecutionService;
        private final UrlAnalysisPersistenceService persistenceService;
        private final UrlAnalysisService urlAnalysisService;
        private final MlAnalysisService mlAnalysisService;
        private final ObjectMapper objectMapper;
        private final FinalRiskAssessmentService finalRiskAssessmentService;
        private final RiskExplanationService riskExplanationService;

        public UrlAnalysisController(
                        UrlNormalizationService normalizationService,
                        UrlRegistrationService registrationService,
                        JevAnalysisService jevAnalysisService,
                        AnalysisVersionService versionService,
                        UrlAnalysisCacheService cacheService,
                        ParallelUrlAnalysisService parallelService,
                        AnalysisRunExecutionService runExecutionService,
                        UrlAnalysisPersistenceService persistenceService,
                        UrlAnalysisService urlAnalysisService,
                        MlAnalysisService mlAnalysisService,
                        ObjectMapper objectMapper,
                        FinalRiskAssessmentService finalRiskAssessmentService,
                        RiskExplanationService riskExplanationService) {

                this.normalizationService = normalizationService;
                this.registrationService = registrationService;
                this.jevAnalysisService = jevAnalysisService;
                this.versionService = versionService;
                this.cacheService = cacheService;
                this.parallelService = parallelService;
                this.runExecutionService = runExecutionService;
                this.persistenceService = persistenceService;
                this.urlAnalysisService = urlAnalysisService;
                this.mlAnalysisService = mlAnalysisService;
                this.objectMapper = objectMapper;
                this.finalRiskAssessmentService = finalRiskAssessmentService;
                this.riskExplanationService = riskExplanationService;
        }

        private static final String POLICY_VERSION = "jev-fusion-v1";

        @PostMapping("/analyze")
        public ResponseEntity<?> analyzeUrl(@RequestBody UrlCollectRequest request) {
            final UrlNormalizationResult normalized;
            try {
                normalized = normalizationService.normalize(request.url());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of("error", "INVALID_URL"));
            }

            var registration = registrationService.register(normalized);
            Long urlId = registration.urlId();
            boolean urlExists = registration.urlExists();
            String ruleVersion = versionService.getRuleVersion();
            String modelVersion = versionService.getModelVersion();
            String normalizationVersion = normalized.normalizationVersion();

            Optional<UrlAnalysis> cached = cacheService.findValidAnalysis(
                    urlId, ruleVersion, modelVersion, normalizationVersion);
            // 기존 정책으로 저장된 캐시는 JEV 최종 판정이 없으므로 재사용하지 않는다.
            cached = cached.filter(saved -> POLICY_VERSION.equals(
                    readMetadata(saved.getFeaturesJson()).get("policyVersion")));

            boolean cacheHit = cached.isPresent();
            boolean savedToDb = false;
            String persistenceStatus = cacheHit ? "EXISTING_CACHE" : "NOT_ATTEMPTED";

            UrlAnalysisService.AnalysisResult analysis;
            MlAnalysisService.MlResult rfAnalysis = null;
            NeuroSymbolicFusionService.FusionResult fusion;
            String rfStatus;
            Map<String, Object> jevResult;
            String runToken = null;

            if (cacheHit) {
                UrlAnalysis saved = cached.get();
                analysis = urlAnalysisService.analyze(normalized.rawUrl(),
                        normalized.normalizedUrl(), normalized.domain());
                if (saved.getRfProbability() != null) {
                    rfAnalysis = mlAnalysisService.restoreCachedResult(saved.getRfProbability());
                    rfStatus = "SUCCESS";
                } else {
                    rfStatus = "UNAVAILABLE";
                }
                double rfProbability = saved.getRfProbability() == null
                        ? 0.0 : saved.getRfProbability().doubleValue();
                double score = saved.getFinalScore().doubleValue();
                // DB의 riskLevel은 JEV 보정 후 등급이므로 원래 융합 등급을 복원한다.
                String fusionLevel = score >= 60 ? "DANGER" : score >= 30 ? "WARNING" : "SAFE";
                fusion = new NeuroSymbolicFusionService.FusionResult(
                        saved.getRuleScore().doubleValue(), rfProbability, score, fusionLevel);
                Map<String, Object> metadata = readMetadata(saved.getFeaturesJson());
                Object storedJev = metadata.get("jevAnalysis");
                jevResult = storedJev instanceof Map<?, ?> map
                        ? stringKeyMap(map)
                        : Map.of("status", "SKIPPED", "reason", "CACHED_NO_JEV");
            } else {
                Optional<String> acquired = runExecutionService.acquireRun(
                        urlId, ruleVersion, modelVersion, normalizationVersion, LEASE_SECONDS);
                if (acquired.isEmpty()) {
                    return ResponseEntity.status(409).body(Map.of(
                            "status", "ANALYSIS_IN_PROGRESS", "urlId", urlId,
                            "message", "해당 URL의 분석이 진행 중이거나 재시도 대기 중입니다."));
                }
                runToken = acquired.get();
                try {
                    ParallelUrlAnalysisService.ParallelResult result = parallelService.analyze(
                            normalized.rawUrl(), normalized.normalizedUrl(), normalized.domain());
                    analysis = result.existingAnalysis();
                    rfAnalysis = result.rfAnalysis();
                    fusion = result.fusionResult();
                    rfStatus = result.rfStatus();
                } catch (RuntimeException e) {
                    failRunSafely(urlId, runToken, "ANALYSIS_FAILED");
                    throw e;
                }

                // JEV는 DB 저장 전에 실행한다. JEV 실패는 기본 융합 판정을 방해하지 않는다.
                jevResult = analyzeJevConditionally(normalized.rawUrl(), analysis, rfAnalysis,
                        rfStatus, fusion);
            }

            FinalRiskAssessmentService.FinalAssessment assessment;
            RiskExplanationService.RiskExplanation explanation;
            try {
                assessment = finalRiskAssessmentService.assess(
                        fusion, analysis.ruleResult(), rfAnalysis,
                        analysis.phishingUrlMatched(), jevResult);
                explanation = riskExplanationService.generate(
                        assessment, analysis.ruleResult(), rfAnalysis, jevResult);
            } catch (RuntimeException e) {
                if (!cacheHit) failRunSafely(urlId, runToken, "ASSESSMENT_FAILED");
                throw e;
            }

            if (cacheHit && !assessment.riskLevel().equals(cached.get().getRiskLevel())) {
                // 저장된 최종 등급과 복원된 판정이 다르면 잘못된 결과를 반환하지 않는다.
                return ResponseEntity.status(409).body(Map.of(
                        "status", "CACHE_INCONSISTENT", "urlId", urlId,
                        "message", "캐시 위험 등급을 재검증해야 합니다."));
            }

            if (!cacheHit) {
                try {
                    BigDecimal rfProbability = null;
                    if ("SUCCESS".equals(rfStatus) && rfAnalysis != null) {
                        rfProbability = BigDecimal.valueOf(rfAnalysis.maliciousProbability())
                                .setScale(6, RoundingMode.HALF_UP);
                    }
                    String ruleFindings = objectMapper.writeValueAsString(
                            analysis.ruleResult().findings());
                    Map<String, Object> metadata = new LinkedHashMap<>();
                    metadata.put("policyVersion", assessment.policyVersion());
                    metadata.put("fusionRiskLevel", assessment.fusionRiskLevel());
                    metadata.put("finalRiskLevel", assessment.riskLevel());
                    metadata.put("riskAdjusted", assessment.riskAdjusted());
                    metadata.put("jevUsed", assessment.jevUsed());
                    metadata.put("decisionReason", assessment.decisionReason());
                    metadata.put("jevAnalysis", jevResult);
                    String featuresJson = objectMapper.writeValueAsString(metadata);
                    LocalDateTime analyzedAt = LocalDateTime.now();
                    persistenceService.saveCompletedAnalysis(
                            urlId, runToken, assessment.riskLevel(),
                            toScore(fusion.finalScore()), toScore(fusion.ruleScore()),
                            rfProbability, ruleFindings, featuresJson,
                            ruleVersion, modelVersion, normalizationVersion,
                            analyzedAt, analyzedAt.plusHours(CACHE_HOURS));
                    savedToDb = true;
                    persistenceStatus = "SAVED";
                } catch (Exception e) {
                    persistenceStatus = "SAVE_FAILED";
                    System.err.println("URL 분석 DB 저장 실패: " + e.getMessage());
                    failRunSafely(urlId, runToken, "PERSISTENCE_FAILED");
                }
            }

            Map<String, Object> mlResult = new LinkedHashMap<>();
            mlResult.put("status", rfStatus);
            if ("SUCCESS".equals(rfStatus) && rfAnalysis != null) {
                mlResult.put("modelVersion", rfAnalysis.modelVersion());
                mlResult.put("maliciousProbability", rfAnalysis.maliciousProbability());
                mlResult.put("prediction", rfAnalysis.prediction());
                mlResult.put("threshold", rfAnalysis.threshold());
            } else {
                mlResult.put("message", "RF 분석을 사용할 수 없습니다.");
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("status", "SUCCESS");
            response.put("normalizedUrl", normalized.normalizedUrl());
            response.put("domain", normalized.domain());
            response.put("ruleAnalysis", analysis.ruleResult());
            response.put("reputationStatus", analysis.reputationStatus());
            response.put("phishingUrlMatched", analysis.phishingUrlMatched());
            response.put("mlAnalysis", mlResult);
            response.put("jevAnalysis", jevResult);
            response.put("fusionAnalysis", fusion);
            response.put("finalScore", fusion.finalScore());
            response.put("finalRiskLevel", assessment.riskLevel());
            response.put("finalAssessment", assessment);
            response.put("riskExplanation", explanation);
            response.put("urlExists", urlExists);
            response.put("urlId", urlId);
            response.put("cacheHit", cacheHit);
            response.put("cacheAvailable", cacheHit);
            response.put("fusionMode", "SUCCESS".equals(rfStatus) ? "RULE_RF" : "RULE_ONLY");
            response.put("savedToDb", savedToDb);
            response.put("persistenceStatus", persistenceStatus);
            return ResponseEntity.ok(response);
        }

        private Map<String, Object> analyzeJevConditionally(
                String rawUrl, UrlAnalysisService.AnalysisResult analysis,
                MlAnalysisService.MlResult rfAnalysis, String rfStatus,
                NeuroSymbolicFusionService.FusionResult fusion) {
            if (analysis.reputationStatus() == DomainReputationService.ReputationStatus.BLACKLISTED) {
                return Map.of("status", "SKIPPED", "reason", "BLACKLISTED_DOMAIN",
                        "message", "블랙리스트 도메인으로 JEV 분석을 생략했습니다.");
            }
            if (!"SUCCESS".equals(rfStatus) || rfAnalysis == null) {
                return Map.of("status", "SKIPPED", "reason", "RF_UNAVAILABLE",
                        "message", "RF 분석 결과가 없어 JEV 분석을 생략했습니다.");
            }
            double ruleScore = fusion.ruleScore();
            double rfScore = rfAnalysis.maliciousProbability() * 100.0;
            double difference = Math.abs(ruleScore - rfScore);
            double average = (ruleScore + rfScore) / 2.0;
            if (difference < 40.0 && (average < 40.0 || average > 60.0)) {
                return Map.of("status", "SKIPPED", "reason", "CONDITION_NOT_MET",
                        "message", "JEV 보조 분석 실행 조건에 해당하지 않습니다.");
            }
            try {
                Map<String, Object> result = jevAnalysisService.analyze(rawUrl);
                return Map.of("status", "COMPLETED", "jevAnalysis", result);
            } catch (RuntimeException e) {
                return Map.of("status", "UNAVAILABLE", "message", "JEV 분석을 사용할 수 없습니다.");
            }
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> readMetadata(String json) {
            if (json == null || json.isBlank()) return Map.of();
            try {
                return objectMapper.readValue(json, Map.class);
            } catch (Exception e) {
                return Map.of();
            }
        }

        private Map<String, Object> stringKeyMap(Map<?, ?> source) {
            Map<String, Object> result = new HashMap<>();
            source.forEach((key, value) -> {
                if (key instanceof String s) result.put(s, value);
            });
            return result;
        }

        private void failRunSafely(Long urlId, String runToken, String reason) {
            if (runToken == null) return;
            try {
                runExecutionService.failRun(urlId, runToken, reason, 30);
            } catch (RuntimeException e) {
                System.err.println("분석 실패 상태 기록 오류: " + e.getMessage());
            }
        }

        private BigDecimal toScore(double value) {
                if (!Double.isFinite(value)) {
                        throw new IllegalArgumentException(
                                        "유효하지 않은 분석 점수입니다.");
                }

                return BigDecimal.valueOf(value)
                                .setScale(2, RoundingMode.HALF_UP);
        }
}