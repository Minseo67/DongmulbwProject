
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import com.dongmulbw.backend.dto.UrlNormalizationResult;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

class RuleAccuracyEvaluationTest {

    private static final Path DATA_DIR = Path.of("..", "ml", "data");

    private final UrlNormalizationService normalizationService = new UrlNormalizationService();

    private final RuleBasedAnalysisService ruleService = new RuleBasedAnalysisService();

    @Test
    void evaluateRuleFeatures() throws IOException {
        evaluate(
                "rule_threshold_valid.csv",
                "rule_threshold_features.csv");
    }

    @Test
    void evaluateUpdatedRuleScores() throws IOException {
        evaluate(
                "rule_threshold_valid.csv",
                "rule_threshold_scores_v2.csv");
    }

    @Test
    void evaluateHttpDotRuleScores() throws IOException {
        evaluate(
                "rule_threshold_valid.csv",
                "rule_threshold_scores_v3.csv");
    }

    private void evaluate(
            String inputFile,
            String outputFile) throws IOException {

        Path inputPath = DATA_DIR.resolve(inputFile);
        Path outputPath = DATA_DIR.resolve(outputFile);

        long total = 0;
        long success = 0;
        long normalizationFailed = 0;

        System.out.println("\n=== 규칙별 분석 시작: " + inputFile + " ===");

        try (
                BufferedReader reader = Files.newBufferedReader(
                        inputPath,
                        StandardCharsets.UTF_8);
                BufferedWriter writer = Files.newBufferedWriter(
                        outputPath,
                        StandardCharsets.UTF_8)) {

            String header = reader.readLine();

            if (!"url,type".equals(header)) {
                throw new IllegalStateException(
                        "CSV 헤더 오류: " + header);
            }

            writer.write(
                    "type,rule_score,status,"
                            + "domain_length,hyphen_count,dot_count,digit_count,"
                            + "has_ip_address,has_punycode,"
                            + "has_suspicious_keyword,has_suspicious_tld,"
                            + "has_brand_impersonation,"
                            + "has_subdomain_brand_impersonation,"
                            + "has_short_url_service");
            writer.newLine();

            String line;

            while ((line = reader.readLine()) != null) {

                total++;

                int lastComma = line.lastIndexOf(',');

                if (lastComma < 0) {
                    throw new IllegalStateException(
                            "CSV 형식 오류: " + total);
                }

                String url = line.substring(0, lastComma);
                String type = line.substring(lastComma + 1);

                if (!type.equals("benign")
                        && !type.equals("phishing")
                        && !type.equals("malware")
                        && !type.equals("defacement")) {
                    throw new IllegalStateException(
                            "알 수 없는 라벨: " + type);
                }

                try {

                    UrlNormalizationResult normalized = normalizationService.normalize(url);

                    RuleAnalysisResult result = ruleService.extract(
                            normalized.normalizedUrl(),
                            normalized.domain());

                    writer.write(
                            type + ","
                                    + result.suspiciousScore() + ",SUCCESS,"
                                    + result.domainLength() + ","
                                    + result.hyphenCount() + ","
                                    + result.dotCount() + ","
                                    + result.digitCount() + ","
                                    + result.hasIpAddress() + ","
                                    + result.hasPunycode() + ","
                                    + result.hasSuspiciousKeyword() + ","
                                    + result.hasSuspiciousTld() + ","
                                    + result.hasBrandImpersonation() + ","
                                    + result.hasSubdomainBrandImpersonation() + ","
                                    + result.hasShortUrlService());

                    success++;

                } catch (IllegalArgumentException e) {

                    writer.write(
                            type + ",,NORMALIZATION_FAILED"
                                    + ",,,,,,,,,,,");

                    normalizationFailed++;
                }

                writer.newLine();

                if (total % 50000 == 0) {
                    System.out.printf(
                            "%s: %,d개 처리 완료%n",
                            inputFile,
                            total);
                }
            }
        }

        System.out.println("전체 URL: " + total);
        System.out.println("분석 성공: " + success);
        System.out.println("정규화 실패: " + normalizationFailed);
        System.out.println("결과 저장: " + outputPath);
    }
}
