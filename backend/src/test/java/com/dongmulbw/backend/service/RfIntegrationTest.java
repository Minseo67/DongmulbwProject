
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RfIntegrationTest {

    @Test
    void testRandomForestPrediction() throws Exception {

        UrlFeatureExtractor extractor =
                new UrlFeatureExtractor();

        String[] urls = {
                "https://www.google.com/",
                "https://www.naver.com/",
                "http://secure-login.example.com/verify-account?confirm=1",
                "example.com/login?user=test"
        };
RfOnnxService rf = new RfOnnxService();

try {
            for (String url : urls) {

                // 1. URL에서 특징 21개 추출
                float[] features =
                        extractor.extractFeatureVector(url);

                assertEquals(21, features.length);

                // Java에서 추출한 21개 특징값 출력
                System.out.println("\n=== JAVA FEATURES ===");
                System.out.println("URL: " + url);

                extractor.extractFeatures(url).forEach(
                        (name, value) ->
                                System.out.println(name + ": " + value)
                );
                
                System.out.println("=====================");

                // 2. ONNX Random Forest 실행
                float probability =
                        rf.predictMaliciousProbability(features);

                // 3. 정상적인 확률인지 확인
                assertTrue(Float.isFinite(probability));
                assertTrue(probability >= 0f);
                assertTrue(probability <= 1f);

                // 4. 임계값 0.50 기준 이진 판정
                int prediction = probability >= 0.50f ? 1 : 0;

                System.out.println("\n========== RF TEST ==========");
                System.out.println("URL: " + url);
                System.out.println("Features: " + features.length);
                System.out.println("Malicious probability: "
                        + probability);
                System.out.println("Prediction: "
                        + (prediction == 1 ? "MALICIOUS" : "BENIGN"));
                System.out.println("=============================");
            }
        } finally {
            rf.close();
        }
    }
}
