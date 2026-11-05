
package com.dongmulbw.backend.service;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import jakarta.annotation.PreDestroy;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;

@Service
public class RfOnnxService {

    private static final int FEATURE_COUNT = 21;
    private static final String MODEL_PATH = "ml/rf_f_base.onnx";
    private static final String INPUT_NAME = "input";
    private static final String OUTPUT_NAME = "probabilities";

    private final OrtEnvironment environment;
    private final OrtSession session;

    public RfOnnxService() throws IOException, OrtException {
        this.environment = OrtEnvironment.getEnvironment();

        byte[] modelBytes = new ClassPathResource(MODEL_PATH)
                .getInputStream().readAllBytes();

        this.session = environment.createSession(
                modelBytes,
                new OrtSession.SessionOptions()
        );

        if (!session.getInputNames().contains(INPUT_NAME)
                || !session.getOutputNames().contains(OUTPUT_NAME)) {
            throw new IllegalStateException(
                    "RF ONNX input/output names do not match expected configuration"
            );
        }

        System.out.println("[RF] ONNX model loaded: " + MODEL_PATH);
    }

    // 특징 21개를 받아 악성 클래스(1)의 확률을 반환
    public float predictMaliciousProbability(float[] features)
            throws OrtException {

        if (features == null || features.length != FEATURE_COUNT) {
            throw new IllegalArgumentException(
                    "RF requires exactly 21 features"
            );
        }

        for (float feature : features) {
            if (!Float.isFinite(feature)) {
                throw new IllegalArgumentException(
                        "RF features must be finite numbers"
                );
            }
        }

        try (
                OnnxTensor tensor = OnnxTensor.createTensor(
                        environment,
                        new float[][]{features}
                );
                OrtSession.Result result = session.run(
                        Map.of(INPUT_NAME, tensor)
                )
        ) {
            var probabilities = result.get(OUTPUT_NAME)
                    .orElseThrow(() ->
                            new IllegalStateException(
                                    "RF probability output missing"
                            )
                    );

            Object value = probabilities.getValue();

            if (!(value instanceof float[][] matrix)
                    || matrix.length != 1
                    || matrix[0].length != 2) {
                throw new IllegalStateException(
                        "Unexpected RF probability output shape"
                );
            }

            return matrix[0][1];
        }
    }

    @PreDestroy
    public void close() throws OrtException {
        session.close();
    }
}
