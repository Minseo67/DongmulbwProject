
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.ParallelUrlAnalysisService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/urls")
public class FusionTestController {

    private final UrlNormalizationService normalizationService;
    private final ParallelUrlAnalysisService parallelService;

    public FusionTestController(
            UrlNormalizationService normalizationService,
            ParallelUrlAnalysisService parallelService) {

        this.normalizationService = normalizationService;
        this.parallelService = parallelService;
    }

    @PostMapping("/analyze/fusion-test")
    public ResponseEntity<?> analyzeFusion(
            @RequestBody UrlCollectRequest request) {

        try {
            // 1. 기존 정규화 서비스 사용
            UrlNormalizationResult normalized =
                    normalizationService.normalize(request.url());

            // 2. 규칙 기반 + RF 병렬 실행 및 결합
            ParallelUrlAnalysisService.ParallelResult result =
                    parallelService.analyze(
                            normalized.rawUrl(),
                            normalized.normalizedUrl(),
                            normalized.domain()
                    );

            // 3. 최종 결합 결과
            var fusion = result.fusionResult();
            var rf = result.rfAnalysis();

            Map<String, Object> response = new LinkedHashMap<>();

            response.put("status", "SUCCESS");
            response.put("analysisType", "NEURO_SYMBOLIC_FUSION");
            response.put("url", normalized.rawUrl());
            response.put("normalizedUrl", normalized.normalizedUrl());
            response.put("domain", normalized.domain());

            response.put("ruleScore", fusion.ruleScore());
            response.put("rfProbability", fusion.rfProbability());
            response.put("rfPrediction", rf.prediction());
            response.put("rfThreshold", rf.threshold());
            response.put("modelVersion", rf.modelVersion());

            response.put("ruleWeight", 0.7);
            response.put("rfWeight", 0.3);

            response.put("finalScore", fusion.finalScore());
            response.put("finalRiskLevel", fusion.finalRiskLevel());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of(
                            "status", "ERROR",
                            "message", e.getMessage() == null
                                    ? "Fusion analysis failed"
                                    : e.getMessage()
                    ));
        }
    }
}
