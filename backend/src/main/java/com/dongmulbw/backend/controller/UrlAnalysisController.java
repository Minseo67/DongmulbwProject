
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
            ObjectMapper objectMapper) {

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
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeUrl(
            @RequestBody UrlCollectRequest request) {

        final UrlNormalizationResult normalized;

        try {
            normalized = normalizationService.normalize(
                    request.url());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }

        // 1. URL 등록 및 방문 횟수 갱신
        var registration = registrationService.register(normalized);

        Long urlId = registration.urlId();
        boolean urlExists = registration.urlExists();

        String ruleVersion = versionService.getRuleVersion();
        String modelVersion = versionService.getModelVersion();
        String normalizationVersion = normalized.normalizationVersion();

        // 2. 캐시 조회
        Optional<UrlAnalysis> cached = cacheService.findValidAnalysis(
                urlId,
                ruleVersion,
                modelVersion,
                normalizationVersion);

        boolean cacheHit = cached.isPresent();
        boolean savedToDb = false;

        String persistenceStatus = cacheHit ? "EXISTING_CACHE" : "NOT_ATTEMPTED";

        UrlAnalysisService.AnalysisResult analysis;
        MlAnalysisService.MlResult rfAnalysis = null;
        NeuroSymbolicFusionService.FusionResult fusion;
        String rfStatus;

        if (cacheHit) {

            // 3-A. 캐시가 있으면 RF/ONNX 추론 생략
            UrlAnalysis saved = cached.get();

            // 상세 규칙 응답 구조를 유지하기 위한 경량 분석
            analysis = urlAnalysisService.analyze(
                    normalized.rawUrl(),
                    normalized.normalizedUrl(),
                    normalized.domain());

            if (saved.getRfProbability() != null) {
                rfAnalysis = mlAnalysisService.restoreCachedResult(
                        saved.getRfProbability());

                rfStatus = "SUCCESS";
            } else {
                rfStatus = "UNAVAILABLE";
            }

            double cachedRfProbability = saved.getRfProbability() == null
                    ? 0.0
                    : saved.getRfProbability().doubleValue();

            // 저장된 최종 점수와 위험 등급 재사용
            fusion = new NeuroSymbolicFusionService.FusionResult(
                    saved.getRuleScore().doubleValue(),
                    cachedRfProbability,
                    saved.getFinalScore().doubleValue(),
                    saved.getRiskLevel());

        } else {

            // 3-B. 캐시가 없으면 새 분석 실행 권한 획득
            Optional<String> runToken = runExecutionService.acquireRun(
                    urlId,
                    ruleVersion,
                    modelVersion,
                    normalizationVersion,
                    LEASE_SECONDS);

            if (runToken.isEmpty()) {
                // 다른 요청이 분석 중일 수 있으므로
                // 중복 분석을 실행하지 않음
                return ResponseEntity.status(409).body(
                        Map.of(
                                "status", "ANALYSIS_IN_PROGRESS",
                                "urlId", urlId,
                                "message",
                                "해당 URL의 분석이 진행 중이거나 재시도 대기 중입니다."));
            }

            ParallelUrlAnalysisService.ParallelResult result;

            try {
                result = parallelService.analyze(
                        normalized.rawUrl(),
                        normalized.normalizedUrl(),
                        normalized.domain());

            } catch (RuntimeException e) {
                try {
                    runExecutionService.failRun(
                            urlId,
                            runToken.get(),
                            "ANALYSIS_FAILED",
                            30);
                } catch (RuntimeException failure) {
                    System.err.println(
                            "분석 실패 기록 오류: "
                                    + failure.getMessage());
                }
                throw e;
            }

            analysis = result.existingAnalysis();
            rfAnalysis = result.rfAnalysis();
            fusion = result.fusionResult();
            rfStatus = result.rfStatus();

            // 4. 새 분석 결과 DB 저장
            try {
                BigDecimal rfProbability = null;

                if ("SUCCESS".equals(rfStatus)
                        && rfAnalysis != null) {

                    rfProbability = BigDecimal.valueOf(
                            rfAnalysis.maliciousProbability())
                            .setScale(
                                    6,
                                    RoundingMode.HALF_UP);
                }

                String ruleFindings = objectMapper.writeValueAsString(
                        analysis.ruleResult().findings());

                LocalDateTime analyzedAt = LocalDateTime.now();

                persistenceService.saveCompletedAnalysis(
                        urlId,
                        runToken.get(),
                        fusion.finalRiskLevel(),
                        toScore(fusion.finalScore()),
                        toScore(fusion.ruleScore()),
                        rfProbability,
                        ruleFindings,
                        null,
                        ruleVersion,
                        modelVersion,
                        normalizationVersion,
                        analyzedAt,
                        analyzedAt.plusHours(CACHE_HOURS));

                savedToDb = true;
                persistenceStatus = "SAVED";

            } catch (Exception e) {
                persistenceStatus = "SAVE_FAILED";

                System.err.println(
                        "URL 분석 DB 저장 실패: "
                                + e.getMessage());

                try {
                    runExecutionService.failRun(
                            urlId,
                            runToken.get(),
                            "PERSISTENCE_FAILED",
                            30);
                } catch (RuntimeException failure) {
                    System.err.println(
                            "실패 상태 기록 오류: "
                                    + failure.getMessage());
                }
            }
        }

        // 5. RF 응답 구성
        Map<String, Object> mlResult = new LinkedHashMap<>();

        mlResult.put("status", rfStatus);

        if ("SUCCESS".equals(rfStatus)
                && rfAnalysis != null) {

            mlResult.put(
                    "modelVersion",
                    rfAnalysis.modelVersion());

            mlResult.put(
                    "maliciousProbability",
                    rfAnalysis.maliciousProbability());

            mlResult.put(
                    "prediction",
                    rfAnalysis.prediction());

            mlResult.put(
                    "threshold",
                    rfAnalysis.threshold());

        } else {
            mlResult.put(
                    "message",
                    "RF 분석을 사용할 수 없습니다.");
        }

        // 6. JEV 기존 실행 조건 유지
        Map<String, Object> jevResult;

        if (analysis.reputationStatus() == DomainReputationService.ReputationStatus.BLACKLISTED) {

            jevResult = Map.of(
                    "status", "SKIPPED",
                    "reason", "BLACKLISTED_DOMAIN",
                    "message",
                    "블랙리스트 도메인으로 JEV 분석을 생략했습니다.");

        } else {
            try {
                jevResult = jevAnalysisService.analyze(
                        normalized.rawUrl());

            } catch (RuntimeException e) {
                jevResult = Map.of(
                        "status", "UNAVAILABLE",
                        "message",
                        "JEV 분석을 사용할 수 없습니다.");
            }
        }

        // 7. 최종 응답
        Map<String, Object> response = new LinkedHashMap<>();

        response.put("status", "SUCCESS");

        response.put(
                "normalizedUrl",
                normalized.normalizedUrl());

        response.put("domain", normalized.domain());

        response.put(
                "ruleAnalysis",
                analysis.ruleResult());

        response.put(
                "reputationStatus",
                analysis.reputationStatus());

        response.put(
                "phishingUrlMatched",
                analysis.phishingUrlMatched());

        response.put("mlAnalysis", mlResult);
        response.put("jevAnalysis", jevResult);

        response.put("fusionAnalysis", fusion);

        response.put(
                "finalScore",
                fusion.finalScore());

        response.put(
                "finalRiskLevel",
                fusion.finalRiskLevel());

        response.put("urlExists", urlExists);
        response.put("urlId", urlId);

        response.put("cacheHit", cacheHit);
        response.put("cacheAvailable", cacheHit);

        response.put(
                "fusionMode",
                "SUCCESS".equals(rfStatus)
                        ? "RULE_RF"
                        : "RULE_ONLY");

        response.put("savedToDb", savedToDb);

        response.put(
                "persistenceStatus",
                persistenceStatus);

        return ResponseEntity.ok(response);
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
