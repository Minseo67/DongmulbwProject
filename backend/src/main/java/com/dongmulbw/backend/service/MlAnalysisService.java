
package com.dongmulbw.backend.service;

import ai.onnxruntime.OrtException;
import org.springframework.stereotype.Service;

@Service
public class MlAnalysisService {

    private static final float THRESHOLD = 0.50f;
    private static final String MODEL_VERSION = "rf_f_v1";

    private final UrlFeatureExtractor featureExtractor;
    private final RfOnnxService rfOnnxService;

    public MlAnalysisService(
            UrlFeatureExtractor featureExtractor,
            RfOnnxService rfOnnxService) {

        this.featureExtractor = featureExtractor;
        this.rfOnnxService = rfOnnxService;
    }

    public MlResult analyze(String originalUrl) throws OrtException {

        // 1. URL에서 특징 21개 추출
        float[] features =
                featureExtractor.extractFeatureVector(originalUrl);

        // 2. ONNX Random Forest 예측
        float probability =
                rfOnnxService.predictMaliciousProbability(features);

        // 3. 확률값 검증
        if (!Float.isFinite(probability)
                || probability < 0f
                || probability > 1f) {
            throw new IllegalStateException(
                    "Invalid RF probability"
            );
        }

        // 4. 이진 분류: 0=정상, 1=악성
        int prediction = probability >= THRESHOLD ? 1 : 0;

        return new MlResult(
                MODEL_VERSION,
                probability,
                prediction,
                THRESHOLD
        );
    }

    public record MlResult(
            String modelVersion,
            float maliciousProbability,
            int prediction,
            float threshold
    ) {
    }
}
