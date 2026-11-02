
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.service.UrlAnalysisService;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.JevAnalysisService; // [JEV 추가]

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.LinkedHashMap; // [JEV 추가]

@RestController
@RequestMapping("/api/urls")
public class UrlAnalysisController {

    private final UrlNormalizationService normalizationService;
    private final UrlAnalysisService analysisService;
    private final JevAnalysisService jevAnalysisService; // [JEV 추가]

    public UrlAnalysisController(
            UrlNormalizationService normalizationService,
            UrlAnalysisService analysisService,
            JevAnalysisService jevAnalysisService) { // [JEV 추가]

        this.normalizationService = normalizationService;
        this.analysisService = analysisService;
        this.jevAnalysisService = jevAnalysisService; // [JEV 추가]
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

            // [JEV 추가] 2-1. Jev 독립 분석
            Map<String, Object> jevResult;

            try {
                // Jev에는 기존 분석 결과가 아닌 원본 URL만 전달
                jevResult = jevAnalysisService.analyze(normalized.rawUrl());

            } catch (RuntimeException e) {
                // Jev 서버에 문제가 발생해도 기존 분석 결과 유지
                jevResult = Map.of(
                        "status", "UNAVAILABLE",
                        "message", "Jev 분석을 사용할 수 없습니다."
                );
            }

            // [JEV 추가] 기존 응답 항목을 그대로 유지하기 위한 Map
            Map<String, Object> response = new LinkedHashMap<>();

            response.put("status", "SUCCESS");
            response.put("normalizedUrl", normalized.normalizedUrl());
            response.put("domain", normalized.domain());
            response.put("ruleAnalysis", analysis.ruleResult());
            response.put("reputationStatus", analysis.reputationStatus());
            response.put("phishingUrlMatched", analysis.phishingUrlMatched());

            // [JEV 추가] Jev 분석 결과만 추가
            response.put("jevAnalysis", jevResult);

            // 3. 결과 반환
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }
    }
}
