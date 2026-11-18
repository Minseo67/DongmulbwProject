
package com.dongmulbw.backend.service;

import ai.onnxruntime.OrtException;
import org.springframework.stereotype.Service;

@Service
public class MlAnalysisService {

        private static final float THRESHOLD = 0.534f;
        private static final String MODEL_VERSION = "G-V6-A-31";

        private final UrlFeatureExtractor featureExtractor;
        private final RfOnnxService rfOnnxService;

        public MlAnalysisService(
                        UrlFeatureExtractor featureExtractor,
                        RfOnnxService rfOnnxService) {
                this.featureExtractor = featureExtractor;
                this.rfOnnxService = rfOnnxService;
        }

        public MlResult analyze(String originalUrl) throws OrtException {

                // G 모델의 31개 특징 추출
                float[] features = featureExtractor.extractFeatureVector(originalUrl);

                // ONNX 추론
                float probability = rfOnnxService.predictMaliciousProbability(features);

                if (!Float.isFinite(probability)
                                || probability < 0f
                                || probability > 1f) {
                        throw new IllegalStateException(
                                        "Invalid RF probability");
                }

                // G 모델 임계값 적용
                int prediction = probability >= THRESHOLD ? 1 : 0;

                return new MlResult(
                                MODEL_VERSION,
                                probability,
                                prediction,
                                THRESHOLD);
        }

        public record MlResult(
                        String modelVersion,
                        float maliciousProbability,
                        int prediction,
                        float threshold) {
        }

        public MlResult restoreCachedResult(
                        java.math.BigDecimal cachedProbability) {

                if (cachedProbability == null) {
                        throw new IllegalArgumentException(
                                        "캐시된 RF 확률이 없습니다.");
                }

                float probability = cachedProbability.floatValue();

                if (!Float.isFinite(probability)
                                || probability < 0f
                                || probability > 1f) {
                        throw new IllegalArgumentException(
                                        "유효하지 않은 캐시 RF 확률입니다.");
                }

                int prediction = probability >= THRESHOLD ? 1 : 0;

                return new MlResult(
                                MODEL_VERSION,
                                probability,
                                prediction,
                                THRESHOLD);
        }
}
