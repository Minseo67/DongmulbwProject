
package com.dongmulbw.backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class GModelOnnxParityTest {

    private static final double TOLERANCE = 1e-4;

    @Test
    void onnxPredictionsMustMatchPython() throws Exception {

        Path current = Path.of("").toAbsolutePath().normalize();

        Path path = current.resolve(
                "ml/models/rf_g_v6_final/test_vectors.json");

        if (!Files.isRegularFile(path)) {
            path = current.resolve("..")
                    .resolve("ml/models/rf_g_v6_final/test_vectors.json")
                    .normalize();
        }

        assertTrue(Files.isRegularFile(path));

        JsonNode root = new ObjectMapper().readTree(path.toFile());
        JsonNode testCases = root.get("test_cases");

        assertEquals(7, testCases.size());

        UrlFeatureExtractor extractor = new UrlFeatureExtractor();
        RfOnnxService onnxService = new RfOnnxService();

        try {
            for (JsonNode testCase : testCases) {

                String url = testCase.get("input_url").asText();
                double expectedProbability =
                        testCase.get("malicious_probability").asDouble();

                float[] features =
                        extractor.extractFeatureVector(url);

                float actualProbability =
                        onnxService.predictMaliciousProbability(features);

                assertEquals(
                        expectedProbability,
                        actualProbability,
                        TOLERANCE,
                        "Probability mismatch: " + url
                );

                int actualPrediction =
                        actualProbability >= 0.534f ? 1 : 0;

                String expectedPrediction =
                        testCase.get("rf_prediction").asText();

                assertEquals(
                        expectedPrediction,
                        actualPrediction == 1 ? "malicious" : "benign",
                        "Prediction mismatch: " + url
                );
            }
        } finally {
            onnxService.close();
        }
    }
}
