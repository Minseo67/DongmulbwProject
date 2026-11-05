
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.service.MlAnalysisService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/urls")
public class MlTestController {

        private final MlAnalysisService mlAnalysisService;

        public MlTestController(MlAnalysisService mlAnalysisService) {
                this.mlAnalysisService = mlAnalysisService;
        }

        @PostMapping("/analyze/ml-test")
        public ResponseEntity<?> analyzeMlOnly(
                        @RequestBody UrlCollectRequest request) {

                if (request == null || request.url() == null
                                || request.url().isBlank()) {
                        return ResponseEntity.badRequest()
                                        .body(Map.of(
                                                        "status", "ERROR",
                                                        "message", "URL이 비어 있습니다."));
                }

                try {
                        // RF F-Base는 원본 URL을 기준으로 특징을 추출
                        MlAnalysisService.MlResult result = mlAnalysisService.analyze(request.url());

                        Map<String, Object> response = new LinkedHashMap<>();

                        response.put("status", "SUCCESS");
                        response.put("analysisType", "RANDOM_FOREST_ONLY");
                        response.put("url", request.url());
                        response.put("modelVersion", result.modelVersion());
                        response.put("maliciousProbability",
                                        result.maliciousProbability());
                        response.put("prediction", result.prediction());
                        response.put("threshold", result.threshold());

                        return ResponseEntity.ok(response);

                } catch (IllegalArgumentException e) {
                        return ResponseEntity.badRequest()
                                        .body(Map.of(
                                                        "status", "ERROR",
                                                        "message", "URL 또는 특징값이 유효하지 않습니다."));

                } catch (Exception e) {
                        return ResponseEntity.internalServerError()
                                        .body(Map.of(
                                                        "status", "ERROR",
                                                        "message", "RF 모델 분석에 실패했습니다."));
                }
        }
}
