
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;

import com.dongmulbw.backend.entity.Url;
import com.dongmulbw.backend.entity.UrlAnalysis;

import com.dongmulbw.backend.repository.UrlRepository;

import com.dongmulbw.backend.service.IntegratedUrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.AnalysisVersionService;
import com.dongmulbw.backend.service.UrlAnalysisCacheService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Optional;

@RestController
@RequestMapping("/api/urls")
public class UrlAnalysisController {

    private static final int HASH_KEY_VERSION = 1;

    private final UrlNormalizationService normalizationService;
    private final IntegratedUrlAnalysisService integratedAnalysisService;
    private final UrlRepository urlRepository;
    private final AnalysisVersionService versionService;
    private final UrlAnalysisCacheService cacheService;

    public UrlAnalysisController(
            UrlNormalizationService normalizationService,
            IntegratedUrlAnalysisService integratedAnalysisService,
            UrlRepository urlRepository,
            AnalysisVersionService versionService,
            UrlAnalysisCacheService cacheService) {

        this.normalizationService = normalizationService;
        this.integratedAnalysisService = integratedAnalysisService;
        this.urlRepository = urlRepository;
        this.versionService = versionService;
        this.cacheService = cacheService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeUrl(
            @RequestBody UrlCollectRequest request) {

        try {
            // 1. URL 정규화
            UrlNormalizationResult normalized = normalizationService.normalize(request.url());

            // 2. 기존 DB URL 조회
            Optional<Url> existingUrl = urlRepository.findByHashKeyVersionAndUrlHash(
                    HASH_KEY_VERSION,
                    normalized.urlHash());

            boolean urlExists = existingUrl.isPresent();
            Long urlId = null;

            if (urlExists) {
                Url savedUrl = existingUrl.get();

                if (!savedUrl.getNormalizedUrl().equals(
                        normalized.normalizedUrl())) {

                    throw new IllegalStateException(
                            "URL 해시 충돌 또는 정규화 결과 불일치");
                }

                urlId = savedUrl.getUrlId();
            }

            // 3. 기존 캐시 조회
            boolean cacheHit = false;

            if (urlId != null) {
                Optional<UrlAnalysis> cachedAnalysis = cacheService.findValidAnalysis(
                        urlId,
                        versionService.getRuleVersion(),
                        versionService.getModelVersion(),
                        normalized.normalizationVersion());

                cacheHit = cachedAnalysis.isPresent();
            }

            // 4. 규칙 기반 + RF + 조건부 JEV 통합 분석
            Map<String, Object> integratedResult = integratedAnalysisService.analyze(
                    normalized.rawUrl(),
                    normalized.normalizedUrl(),
                    normalized.domain());

            // 5. 기존 응답 구조 유지
            Map<String, Object> response = new LinkedHashMap<>();

            response.put("status",
                    integratedResult.get("status"));

            response.put("normalizedUrl",
                    normalized.normalizedUrl());

            response.put("domain",
                    normalized.domain());

            // 기존 규칙 분석 결과 구조 복원
            Object ruleResult = integratedResult.get("ruleAnalysis");

            if (ruleResult instanceof com.dongmulbw.backend.service.UrlAnalysisService.AnalysisResult analysis) {

                response.put("ruleAnalysis",
                        analysis.ruleResult());

                response.put("reputationStatus",
                        analysis.reputationStatus());

                response.put("phishingUrlMatched",
                        analysis.phishingUrlMatched());
            }

            // 6. RF 분석 결과 추가
            response.put("mlAnalysis",
                    integratedResult.get("mlAnalysis"));

            // 7. JEV 조건부 분석 결과 추가
            response.put("jevTriggered",
                    integratedResult.get("jevTriggered"));

            response.put("jevStatus",
                    integratedResult.get("jevStatus"));

            response.put("jevAnalysis",
                    integratedResult.get("jevAnalysis"));

            response.put("jevElapsedMs",
                    integratedResult.get("jevElapsedMs"));

            // 최종 위험 등급 통합 결과
            response.put("finalAssessment", integratedResult.get("finalAssessment"));

            // 사용자용 자연어 설명
            response.put("riskExplanation", integratedResult.get("riskExplanation"));

            // 8. 기존 DB 정보 유지
            response.put("urlExists", urlExists);
            response.put("urlId", urlId);

            // 9. 기존 캐시 정보 유지
            response.put("cacheHit", cacheHit);

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }
    }
}
