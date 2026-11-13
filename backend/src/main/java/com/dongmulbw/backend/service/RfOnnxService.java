package com.dongmulbw.backend.service;

import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@Service
public class RfOnnxService {

    private static final int FEATURE_COUNT = 31;
    private static final String MODEL_FILE =
            "ml/models/rf_g_v6_final/G-V6-A-31.onnx";

    private static final String INPUT_NAME = "X";
    private static final String OUTPUT_NAME = "probabilities";

    private final OrtEnvironment environment;
    private final OrtSession session;

    public RfOnnxService() throws IOException, OrtException {
        environment = OrtEnvironment.getEnvironment();

        Path current = Path.of("").toAbsolutePath().normalize();
        Path modelPath = current.resolve(MODEL_FILE);

        // backend 폴더에서 실행한 경우 프로젝트 루트 탐색
        if (!Files.isRegularFile(modelPath)) {
            modelPath = current.resolve("..")
                    .resolve(MODEL_FILE).normalize();
        }

        if (!Files.isRegularFile(modelPath)) {
            throw new IOException(
                    "G model not found. Current directory: " + current);
        }

        session = environment.createSession(
                modelPath.toString(),
                new OrtSession.SessionOptions()
        );

        if (!session.getInputNames().contains(INPUT_NAME)
                || !session.getOutputNames().contains(OUTPUT_NAME)) {
            throw new IllegalStateException(
                    "Unexpected ONNX input/output names. Inputs="
                    + session.getInputNames()
                    + ", outputs=" + session.getOutputNames()
            );
        }

        System.out.println("[RF] G-V6-A-31 loaded: " + modelPath);
    }

    public float predictMaliciousProbability(float[] features)
            throws OrtException {

        if (features == null || features.length != FEATURE_COUNT) {
            throw new IllegalArgumentException(
                    "G model requires exactly 31 features");
        }

        for (float value : features) {
            if (!Float.isFinite(value)) {
                throw new IllegalArgumentException(
                        "RF features must be finite numbers");
            }
        }

        try (
            OnnxTensor tensor = OnnxTensor.createTensor(
                    environment, new float[][] { features });
            OrtSession.Result result = session.run(
                    Map.of(INPUT_NAME, tensor))
        ) {
            Object value = result.get(OUTPUT_NAME)
                    .orElseThrow(() -> new IllegalStateException(
                            "RF probability output missing"))
                    .getValue();

            if (!(value instanceof float[][] matrix)
                    || matrix.length != 1
                    || matrix[0].length != 2) {
                throw new IllegalStateException(
                        "Unexpected RF probability output: "
                        + value.getClass().getName());
            }

            return matrix[0][1];
        }
    }

    @PreDestroy
    public void close() throws OrtException {
        session.close();
    }
}
