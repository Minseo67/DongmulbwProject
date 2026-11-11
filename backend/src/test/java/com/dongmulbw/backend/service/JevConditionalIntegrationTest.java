
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@EnabledIfEnvironmentVariable(
        named = "RUN_JEV_INTEGRATION_TEST",
        matches = "true"
)
class JevConditionalIntegrationTest {

    private final JevTriggerService triggerService =
            new JevTriggerService();

    private final JevAnalysisService jevAnalysisService =
            new JevAnalysisService(
                    "http://127.0.0.1:8000"
            );

    private final JevConditionalAnalysisService conditionalService =
            new JevConditionalAnalysisService(
                    triggerService,
                    jevAnalysisService
            );

    @Test
    void 조건을_충족하지_않으면_JEV를_생략한다() {

        Map<String, Object> result =
                conditionalService.analyze(
                        "https://www.google.com",
                        10.0,
                        0.10
                );

        assertEquals(false, result.get("jevTriggered"));
        assertEquals("SKIPPED", result.get("status"));
        assertNull(result.get("jevAnalysis"));
    }

    @Test
    void 분석_결과가_불일치하면_JEV를_실행한다() {

        Map<String, Object> result =
                conditionalService.analyze(
                        "https://www.google.com",
                        85.0,
                        0.15
                );

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("COMPLETED", result.get("status"));
        assertNotNull(result.get("jevAnalysis"));
    }

    @Test
    void 판단이_불확실하면_JEV를_실행한다() {

        Map<String, Object> result =
                conditionalService.analyze(
                        "https://www.google.com",
                        50.0,
                        0.50
                );

        assertEquals(true, result.get("jevTriggered"));
        assertEquals("COMPLETED", result.get("status"));
        assertNotNull(result.get("jevAnalysis"));
    }
}
