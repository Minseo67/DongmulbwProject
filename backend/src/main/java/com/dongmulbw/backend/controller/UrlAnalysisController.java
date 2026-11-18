package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;

import com.dongmulbw.backend.entity.Url;
import com.dongmulbw.backend.entity.UrlAnalysis;

import com.dongmulbw.backend.repository.UrlRepository;

import com.dongmulbw.backend.service.UrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.JevAnalysisService; // [JEV 추가]
import com.dongmulbw.backend.service.AnalysisVersionService;
import com.dongmulbw.backend.service.DomainReputationService;
import com.dongmulbw.backend.service.UrlAnalysisCacheService;
import com.dongmulbw.backend.service.MlAnalysisService;
import ai.onnxruntime.OrtException;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.LinkedHashMap; // [JEV 추가]
import java.util.Optional;

@RestController
@RequestMapping("/api/urls")
public class UrlAnalysisController {

    private final UrlNormalizationService normalizationService;
    private final UrlAnalysisService analysisService;
    private final JevAnalysisService jevAnalysisService; // [JEV 추가]
    // [DB 조회 추가] 기존 URL 존재 여부 확인
    private static final int HASH_KEY_VERSION = 1;
    private final UrlRepository urlRepository;
    // [캐시 조회 추가]
    private final AnalysisVersionService versionService;
    private final UrlAnalysisCacheService cacheService;
    // Random Forest 기반 악성 URL 분석 서비스
    private final MlAnalysisService mlAnalysisService;

    public UrlAnalysisController(
            UrlNormalizationService normalizationService,
            UrlAnalysisService analysisService,
            JevAnalysisService jevAnalysisService,
            UrlRepository urlRepository, // [JEV 추가]
            AnalysisVersionService versionService,
            UrlAnalysisCacheService cacheService,
            MlAnalysisService mlAnalysisService) {

        this.normalizationService = normalizationService;
        this.analysisService = analysisService;
        this.jevAnalysisService = jevAnalysisService; // [JEV 추가]
        // [DB 조회 추가]
        this.urlRepository = urlRepository;
        // [캐시 조회 추가]
        this.versionService = versionService;
        this.cacheService = cacheService;
        // Spring이 주입한 Random Forest 분석 서비스 보관
        this.mlAnalysisService = mlAnalysisService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeUrl(
            @RequestBody UrlCollectRequest request) {

        try {
            // 1. 원본 URL 정규화
            UrlNormalizationResult normalized = normalizationService.normalize(request.url());

            // [DB 조회 추가] 기존 URL 존재 여부 확인
            Optional<Url> existingUrl = urlRepository.findByHashKeyVersionAndUrlHash(
                    HASH_KEY_VERSION,
                    normalized.urlHash());

            boolean urlExists = existingUrl.isPresent();
            Long urlId = null;

            if (urlExists) {
                Url savedUrl = existingUrl.get();

                // 해시가 같더라도 정규화 URL이 일치하는지 확인
                if (!savedUrl.getNormalizedUrl().equals(
                        normalized.normalizedUrl())) {

                    throw new IllegalStateException(
                            "URL 해시 충돌 또는 정규화 결과 불일치");
                }

                urlId = savedUrl.getUrlId();
            }

            // [캐시 조회 추가] 현재 분석 버전과 일치하는 유효한 결과 확인
            boolean cacheHit = false;

            if (urlId != null) {
                Optional<UrlAnalysis> cachedAnalysis = cacheService.findValidAnalysis(
                        urlId,
                        versionService.getRuleVersion(),
                        versionService.getModelVersion(),
                        normalized.normalizationVersion());

                cacheHit = cachedAnalysis.isPresent();
            }

            // 2. 규칙 기반 분석 + DB 도메인 평판 + 피싱 URL 조회
            UrlAnalysisService.AnalysisResult analysis = analysisService.analyze(
                    normalized.rawUrl(),
                    normalized.normalizedUrl(),
                    normalized.domain());

            // [JEV 추가] 2-1. Jev 독립 분석

            // 2-1. 도메인 평판에 따라 JEV 분석 실행 여부 결정
            Map<String, Object> jevResult;

            if (analysis.reputationStatus() == DomainReputationService.ReputationStatus.BLACKLISTED) {

                // 블랙리스트는 규칙 기반 분석에서 이미 100점으로 확정
                // 불필요한 JEV 서버 호출을 생략하여 분석 시간 절약
                jevResult = Map.of(
                        "status", "SKIPPED",
                        "reason", "BLACKLISTED_DOMAIN",
                        "message", "블랙리스트 도메인으로 JEV 분석을 생략했습니다.");

            } else {
                try {
                    // 일반 및 화이트리스트 도메인은 기존 JEV 분석 유지
                    // 화이트리스트 -10점은 규칙 점수에만 적용
                    jevResult = jevAnalysisService.analyze(normalized.rawUrl());

                } catch (RuntimeException e) {
                    // JEV 서버 오류가 발생해도 규칙 기반 분석 결과 유지
                    jevResult = Map.of(
                            "status", "UNAVAILABLE",
                            "message", "JEV 분석을 사용할 수 없습니다.");
                }
            }

            // [JEV 추가] 기존 응답 항목을 그대로 유지하기 위한 Map
            Map<String, Object> response = new LinkedHashMap<>();

            // 2-2. Random Forest 기반 악성 URL 분석
            // 화이트리스트의 -10점 보정은 규칙 점수에만 적용하며,
            // RF 악성 확률은 변경하지 않는다.
            Map<String, Object> mlResult = new LinkedHashMap<>();

            if (analysis.reputationStatus() == DomainReputationService.ReputationStatus.BLACKLISTED) {

                // 블랙리스트는 위험도 100점으로 확정되므로 RF 추론 생략
                mlResult.put("status", "SKIPPED");
                mlResult.put("reason", "BLACKLISTED_DOMAIN");

            } else {
                try {
                    // 기존 ONNX 모델을 사용해 원본 URL 분석
                    MlAnalysisService.MlResult prediction = mlAnalysisService.analyze(normalized.rawUrl());

                    mlResult.put("status", "SUCCESS");
                    mlResult.put("modelVersion", prediction.modelVersion());
                    mlResult.put("maliciousProbability",
                            prediction.maliciousProbability());
                    mlResult.put("prediction", prediction.prediction());
                    mlResult.put("threshold", prediction.threshold());

                } catch (OrtException | RuntimeException e) {
                    // RF 추론 실패 시에도 규칙 기반 분석 결과는 유지
                    mlResult.put("status", "UNAVAILABLE");
                    mlResult.put("message", "RF 분석을 사용할 수 없습니다.");
                }
            }

            // 기존 응답 필드를 변경하지 않고 RF 결과 추가
            response.put("mlAnalysis", mlResult);

            response.put("status", "SUCCESS");
            response.put("normalizedUrl", normalized.normalizedUrl());
            response.put("domain", normalized.domain());
            response.put("ruleAnalysis", analysis.ruleResult());
            response.put("reputationStatus", analysis.reputationStatus());
            response.put("phishingUrlMatched", analysis.phishingUrlMatched());

            // [JEV 추가] Jev 분석 결과만 추가
            response.put("jevAnalysis", jevResult);

            // [DB 조회 추가] URL 저장 여부 및 ID 반환
            response.put("urlExists", urlExists);
            response.put("urlId", urlId);

            // 도메인 평판이 블랙리스트 또는 화이트리스트인 경우
            // 기존 분석 캐시가 현재 평판 정책을 반영했는지 보장할 수 없으므로
            // 캐시 적중으로 표시하지 않는다.
            boolean reputationSensitive = analysis
                    .reputationStatus() == DomainReputationService.ReputationStatus.BLACKLISTED
                    || analysis.reputationStatus() == DomainReputationService.ReputationStatus.WHITELISTED;

            // 실제 캐시 조회 결과와 평판 정책을 함께 고려
            // 주의: 현재는 캐시 재사용 여부가 아닌 캐시 적중 표시만 제어한다.
            boolean effectiveCacheHit = cacheHit && !reputationSensitive;

            response.put("cacheHit", effectiveCacheHit);

            // 3. 결과 반환
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }
    }
}
