
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RfIntegrationTest {

    private static final int FEATURE_COUNT = 31;
    private static final float THRESHOLD = 0.534f;

    @Test
    void testRandomForestPrediction() throws Exception {

        UrlFeatureExtractor extractor = new UrlFeatureExtractor();

        String[] urls = {
                "https://www.google.com/",
                "https://www.naver.com/",
                "http://secure-login.example.com/verify-account?confirm=1",
                "example.com/login?user=test"
        };

        RfOnnxService rf = new RfOnnxService();

        try {
            for (String url : urls) {

                // 1. G 모델 입력 특징 31개 추출
                float[] features =
                        extractor.extractFeatureVector(url);

                assertEquals(
                        FEATURE_COUNT,
                        features.length,
                        "G-V6-A-31 모델의 특징 개수는 31개여야 합니다."
                );

                // 2. Java 특징 추출 결과 출력
                System.out.println("\n=== JAVA FEATURES ===");
                System.out.println("URL: " + url);

                extractor.extractFeatures(url).forEach(
                        (name, value) ->
                                System.out.println(name + ": " + value)
                );

                System.out.println("=====================");

                // 3. ONNX Random Forest 추론
                float probability =
                        rf.predictMaliciousProbability(features);

                // 4. 악성 확률 유효성 검증
                assertTrue(
                        Float.isFinite(probability),
                        "예측 확률은 유한한 숫자여야 합니다."
                );

                assertTrue(
                        probability >= 0f && probability <= 1f,
                        "예측 확률은 0~1 범위여야 합니다."
                );

                // 5. 최종 임계값 0.534 적용
                int prediction =
                        probability >= THRESHOLD ? 1 : 0;

                // 6. 결과 출력
                System.out.println("\n========== RF G MODEL TEST ==========");
                System.out.println("Model: G-V6-A-31");
                System.out.println("URL: " + url);
                System.out.println("Features: " + features.length);
                System.out.println("Threshold: " + THRESHOLD);
                System.out.println("Malicious probability: " + probability);
                System.out.println(
                        "Prediction: " +
                        (prediction == 1 ? "MALICIOUS" : "BENIGN")
                );
                System.out.println("=====================================");
            }
        } finally {
            rf.close();
        }
    }
}
