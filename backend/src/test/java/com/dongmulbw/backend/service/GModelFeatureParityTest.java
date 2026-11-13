
package com.dongmulbw.backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class GModelFeatureParityTest {

    private static final double TOLERANCE = 1e-4;

    private static final String VECTOR_PATH =
            "ml/models/rf_g_v6_final/test_vectors.json";

    @Test
    void javaFeaturesMustMatchPythonReference() throws Exception {

        Path current = Path.of("")
                .toAbsolutePath()
                .normalize();

        Path path = current.resolve(VECTOR_PATH);

        if (!Files.isRegularFile(path)) {
            path = current.resolve("..")
                    .resolve(VECTOR_PATH)
                    .normalize();
        }

        assertTrue(
                Files.isRegularFile(path),
                "test_vectors.json not found: " + path
        );

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(path.toFile());

        JsonNode featureOrder = root.get("feature_order");
        JsonNode testCases = root.get("test_cases");

        assertNotNull(featureOrder);
        assertNotNull(testCases);
        assertEquals(31, featureOrder.size());
        assertEquals(7, testCases.size());

        UrlFeatureExtractor extractor = new UrlFeatureExtractor();

        int mismatchCount = 0;
        StringBuilder report = new StringBuilder();

        for (JsonNode testCase : testCases) {

            String url = testCase.get("input_url").asText();
            JsonNode expectedFeatures = testCase.get("features");

            float[] actual = extractor.extractFeatureVector(url);

            assertEquals(
                    31,
                    actual.length,
                    "Feature count mismatch: " + url
            );

            for (int i = 0; i < featureOrder.size(); i++) {

                String name = featureOrder.get(i).asText();

                assertTrue(
                        expectedFeatures.has(name),
                        "Missing reference feature: " + name
                );

                double expected =
                        expectedFeatures.get(name).asDouble();

                double received = actual[i];

                double difference =
                        Math.abs(expected - received);

                if (difference > TOLERANCE) {

                    mismatchCount++;

                    report.append("\nURL: ")
                            .append(url)
                            .append("\nFeature: ")
                            .append(name)
                            .append("\nPython: ")
                            .append(expected)
                            .append("\nJava: ")
                            .append(received)
                            .append("\nDifference: ")
                            .append(difference)
                            .append("\n");
                }
            }
        }

        assertEquals(
                0,
                mismatchCount,
                "Python/Java feature mismatches: "
                        + mismatchCount
                        + "\n"
                        + report
        );
    }
}
