
package com.dongmulbw.backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;

@Service
public class JevAnalysisService {

    private final RestClient restClient;

    public JevAnalysisService(
            @Value("${jev.api.url:http://127.0.0.1:8000}") String apiUrl) {

        this.restClient = RestClient.builder()
                .baseUrl(apiUrl)
                .build();
    }

    public Map<String, Object> analyze(String rawUrl) {

        try {
            Map<String, Object> response = restClient.post()
                    .uri("/detect")
                    .body(Map.of("url", rawUrl))
                    .retrieve()
                    .body(Map.class);

            if (response == null
                    || !response.containsKey("jevAnalysis")) {
                throw new IllegalStateException(
                        "Jev 분석 응답이 올바르지 않습니다.");
            }

            Object analysis = response.get("jevAnalysis");

            if (!(analysis instanceof Map<?, ?>)) {
                throw new IllegalStateException(
                        "Jev 분석 결과 형식이 올바르지 않습니다.");
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> result =
                    (Map<String, Object>) analysis;

            return result;

        } catch (RestClientException e) {
            throw new IllegalStateException(
                    "Jev FastAPI 서버 통신 실패", e);
        }
    }
}
