package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.UrlNormalizationResult;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RuleV3TestEvaluationTest {

    private final UrlNormalizationService normalizationService =
            new UrlNormalizationService();

    private final RuleBasedAnalysisService ruleService =
            new RuleBasedAnalysisService();

    @Test
    void evaluateFinalTestDataset() throws Exception {

        Path input = Path.of("..", "ml", "data", "rule_test_valid.csv");

        long tp = 0, tn = 0, fp = 0, fn = 0;
        long failed = 0, total = 0;

        try (BufferedReader reader = Files.newBufferedReader(
                input, StandardCharsets.UTF_8)) {

            String header = reader.readLine();
            assertEquals("url,type", header);

            String line;

            while ((line = reader.readLine()) != null) {

                total++;

                int separator = line.lastIndexOf(',');

                if (separator < 0) {
                    throw new IllegalArgumentException(
                            "Invalid CSV row: " + total);
                }

                String url = line.substring(0, separator);
                String label = line.substring(separator + 1);

                boolean actualMalicious = switch (label) {
                    case "benign" -> false;
                    case "phishing", "malware", "defacement" -> true;
                    default -> throw new IllegalArgumentException(
                            "Unknown label: " + label);
                };

                try {
                    UrlNormalizationResult normalized =
                            normalizationService.normalize(url);

                    double score = ruleService.extract(
                            normalized.normalizedUrl(),
                            normalized.domain()
                    ).suspiciousScore();

                    boolean predictedMalicious = score >= 10;

                    if (actualMalicious && predictedMalicious) {
                        tp++;
                    } else if (!actualMalicious && !predictedMalicious) {
                        tn++;
                    } else if (!actualMalicious) {
                        fp++;
                    } else {
                        fn++;
                    }

                } catch (IllegalArgumentException e) {
                    failed++;
                }
            }
        }

        long evaluated = tp + tn + fp + fn;

        double accuracy = (double) (tp + tn) / evaluated;
        double precision = tp + fp == 0 ? 0 :
                (double) tp / (tp + fp);
        double recall = tp + fn == 0 ? 0 :
                (double) tp / (tp + fn);
        double f1 = precision + recall == 0 ? 0 :
                2 * precision * recall / (precision + recall);
        double fpr = fp + tn == 0 ? 0 :
                (double) fp / (fp + tn);

        System.out.println("=== RULE V3 FINAL TEST ===");
        System.out.println("Total: " + total);
        System.out.println("Evaluated: " + evaluated);
        System.out.println("Normalization failed: " + failed);
        System.out.printf("Accuracy: %.4f%n", accuracy);
        System.out.printf("Precision: %.4f%n", precision);
        System.out.printf("Recall: %.4f%n", recall);
        System.out.printf("F1: %.4f%n", f1);
        System.out.printf("FPR: %.4f%n", fpr);
        System.out.println("TP: " + tp);
        System.out.println("TN: " + tn);
        System.out.println("FP: " + fp);
        System.out.println("FN: " + fn);

        assertEquals(total, evaluated + failed);
    }
}
