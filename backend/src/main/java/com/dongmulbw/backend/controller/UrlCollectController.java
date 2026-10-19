
package com.dongmulbw.backend.controller;

import com.dongmulbw.backend.dto.UrlCollectRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api/urls")
public class UrlCollectController {

    @PostMapping("/collect")
    public ResponseEntity<?> collectUrl(
            @RequestBody UrlCollectRequest request) {

        String url = request.url();

        if (url == null || url.isBlank() || url.length() > 2048) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }

        try {
            URI uri = URI.create(url);

            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (scheme == null
                    || (!scheme.equalsIgnoreCase("http")
                            && !scheme.equalsIgnoreCase("https"))
                    || host == null
                    || host.isBlank()) {

                return ResponseEntity.badRequest()
                        .body(Map.of("error", "INVALID_URL"));
            }

            // 확인용 콘솔 출력
            System.out.println("=================================");
            System.out.println("[URL 자동 수집]");
            System.out.println("수신 URL: " + url);
            System.out.println("도메인: " + host);
            System.out.println("수신 상태: SUCCESS");
            System.out.println("=================================");

            return ResponseEntity.ok(Map.of(
                    "status", "SUCCESS",
                    "url", url));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "INVALID_URL"));
        }
    }
}
