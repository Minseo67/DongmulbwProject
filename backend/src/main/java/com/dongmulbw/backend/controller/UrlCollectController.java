
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.entity.Url;
import com.dongmulbw.backend.service.UrlNormalizationService;
import com.dongmulbw.backend.service.UrlStorageService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/urls")
public class UrlCollectController {

    private final UrlNormalizationService normalizationService;
    private final UrlStorageService storageService;

    public UrlCollectController(
            UrlNormalizationService normalizationService,
            UrlStorageService storageService) {
        this.normalizationService = normalizationService;
        this.storageService = storageService;
    }

    @PostMapping("/collect")
    public ResponseEntity<?> collectUrl(
            @RequestBody UrlCollectRequest request) {
        try {
            // 1. 원본 URL 정규화
            UrlNormalizationResult result = normalizationService.normalize(request.url());

            // 2. DB 저장 또는 중복 갱신
            Url savedUrl = storageService.saveOrUpdate(result);

            // 3. 저장 결과 반환
            return ResponseEntity.ok(Map.of(
                    "status", "SUCCESS",
                    "urlId", savedUrl.getUrlId(),
                    "normalizedUrl", savedUrl.getNormalizedUrl(),
                    "urlHash", savedUrl.getUrlHash(),
                    "normalizationVersion",
                    savedUrl.getNormalizationVersion()));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }
    }
}
