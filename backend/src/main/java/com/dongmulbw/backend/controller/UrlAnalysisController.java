
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.service.UrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/urls")
public class UrlAnalysisController {

    private final UrlNormalizationService normalizationService;
    private final UrlAnalysisService analysisService;

    public UrlAnalysisController(
            UrlNormalizationService normalizationService,
            UrlAnalysisService analysisService) {

        this.normalizationService = normalizationService;
        this.analysisService = analysisService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeUrl(
            @RequestBody UrlCollectRequest request) {

        try {
            // 1. 원본 URL 정규화
            UrlNormalizationResult normalized = normalizationService.normalize(request.url());

            // 2. 규칙 기반 분석 + DB 도메인 평판 + 피싱 URL 조회
            UrlAnalysisService.AnalysisResult analysis = analysisService.analyze(
                    normalized.rawUrl(),
                    normalized.normalizedUrl(),
                    normalized.domain());

            // 3. 결과 반환
            return ResponseEntity.ok(Map.of(
                    "status", "SUCCESS",
                    "normalizedUrl", normalized.normalizedUrl(),
                    "domain", normalized.domain(),
                    "ruleAnalysis", analysis.ruleResult(),
                    "reputationStatus", analysis.reputationStatus(),
                    "phishingUrlMatched", analysis.phishingUrlMatched()));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }
    }
}
