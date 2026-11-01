
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

class RuleAnalysisJsonServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RuleAnalysisJsonService jsonService = new RuleAnalysisJsonService(objectMapper);

    private final RuleBasedAnalysisService analysisService = new RuleBasedAnalysisService();

    @Test
    void normalUrlToJson() {
        RuleAnalysisResult result = analysisService.extract(
                "https://example.com",
                "example.com");

        String json = jsonService.toJson(result);
        JsonNode node = objectMapper.readTree(json);

        assertNotNull(json);
        assertEquals(0.0, node.get("suspiciousScore").asDouble());
        assertFalse(node.get("hasIpAddress").asBoolean());
        assertFalse(node.get("hasBrandImpersonation").asBoolean());
    }

    @Test
    void suspiciousUrlToJson() {
        RuleAnalysisResult result = analysisService.extract(
                "https://google-login.xyz",
                "google-login.xyz");

        String json = jsonService.toJson(result);
        JsonNode node = objectMapper.readTree(json);

        assertTrue(node.get("hasSuspiciousKeyword").asBoolean());
        assertTrue(node.get("hasSuspiciousTld").asBoolean());
        assertTrue(node.get("hasBrandImpersonation").asBoolean());
        assertEquals(100.0, node.get("suspiciousScore").asDouble());
    }

    @Test
    void allFieldsIncluded() {
        RuleAnalysisResult result = analysisService.extract(
                "https://example.com/login",
                "example.com");

        String json = jsonService.toJson(result);
        JsonNode node = objectMapper.readTree(json);

        assertEquals(12, node.size());

        assertTrue(node.has("domainLength"));
        assertTrue(node.has("hyphenCount"));
        assertTrue(node.has("dotCount"));
        assertTrue(node.has("digitCount"));
        assertTrue(node.has("hasIpAddress"));
        assertTrue(node.has("hasPunycode"));
        assertTrue(node.has("hasSuspiciousKeyword"));
        assertTrue(node.has("hasSuspiciousTld"));
        assertTrue(node.has("hasBrandImpersonation"));
        assertTrue(node.has("hasSubdomainBrandImpersonation"));
        assertTrue(node.has("hasShortUrlService"));
        assertTrue(node.has("suspiciousScore"));
    }

    @Test
    void nullResultThrowsException() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> jsonService.toJson(null));

        assertEquals(
                "규칙 기반 분석 결과가 null입니다.",
                exception.getMessage());
    }
}
