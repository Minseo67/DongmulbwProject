
package com.dongmulbw.backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;
import java.util.Set;

@Service
public class JevAnalysisService {

    private static final Set<String> VALID_RISK_LEVELS =
            Set.of("safe", "caution", "danger", "unknown");

    private final RestClient restClient;

    public JevAnalysisService(
            @Value("${jev.api.url:http://127.0.0.1:8000}") String apiUrl) {

        SimpleClientHttpRequestFactory requestFactory =
                new SimpleClientHttpRequestFactory();

        // FastAPI 서버 연결 제한 시간: 2초
        requestFactory.setConnectTimeout(2000);

        // FastAPI 서버 응답 제한 시간: 5초
        requestFactory.setReadTimeout(5000);

        this.restClient = RestClient.builder()
                .baseUrl(apiUrl)
                .requestFactory(requestFactory)
                .build();
    }

    public Map<String, Object> analyze(String rawUrl) {

        if (rawUrl == null || rawUrl.isBlank()) {
            throw new IllegalArgumentException(
                    "분석할 URL이 비어 있습니다.");
        }

        try {
            // 1. FastAPI에 URL 분석 요청
            Map<?, ?> response = restClient.post()
                    .uri("/detect")
                    .body(Map.of("url", rawUrl))
                    .retrieve()
                    .body(Map.class);

            // 2. 응답 존재 여부 확인
            if (response == null) {
                throw new IllegalStateException(
                        "JEV 응답이 비어 있습니다.");
            }

            // 3. FastAPI 분석 성공 여부 확인
            if (!"SUCCESS".equals(response.get("status"))) {
                throw new IllegalStateException(
                        "JEV 분석이 정상 완료되지 않았습니다.");
            }

            // 4. JEV 분석 결과 추출
            Object analysis = response.get("jevAnalysis");

            if (!(analysis instanceof Map<?, ?> result)) {
                throw new IllegalStateException(
                        "JEV 분석 결과 형식이 올바르지 않습니다.");
            }

            // 5. 위험 등급 검증
            Object riskLevel = result.get("risk_level");

            if (!(riskLevel instanceof String level)
                    || !VALID_RISK_LEVELS.contains(level)) {
                throw new IllegalStateException(
                        "JEV 위험 등급이 올바르지 않습니다.");
            }

            // 6. 분석 결과 반환
            Map<String, Object> validatedResult =
                    new java.util.LinkedHashMap<>();

            for (Map.Entry<?, ?> entry : result.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new IllegalStateException(
                            "JEV 결과 필드명이 올바르지 않습니다.");
                }
                validatedResult.put(key, entry.getValue());
            }

            return validatedResult;

        } catch (RestClientException e) {
            // 통신 오류, HTTP 오류, 타임아웃 등 처리
            throw new IllegalStateException(
                    "JEV FastAPI 서버 통신 실패", e);
        }
    }
}
