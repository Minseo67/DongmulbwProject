
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NeuroSymbolicFusionServiceTest {

    private final NeuroSymbolicFusionService fusionService =
            new NeuroSymbolicFusionService();

    private RuleAnalysisResult rule(double score) {
        return new RuleAnalysisResult(
                0, 0, 0, 0,
                false, false, false, false,
                false, false, false,
                0, score, "SAFE",
                java.util.List.of()
        );
    }

    private MlAnalysisService.MlResult rf(float probability) {
        return new MlAnalysisService.MlResult(
                "G-V6-A-31",
                probability,
                probability >= 0.534f ? 1 : 0,
                0.534f
        );
    }

    @Test
    void safeResult() {
        var result = fusionService.fuse(rule(10), rf(0.2f));

        assertEquals(13.0, result.finalScore(), 0.0001);
        assertEquals("SAFE", result.finalRiskLevel());
    }

    @Test
    void warningResult() {
        var result = fusionService.fuse(rule(40), rf(0.8f));

        assertEquals(52.0, result.finalScore(), 0.0001);
        assertEquals("WARNING", result.finalRiskLevel());
    }

    @Test
    void dangerResult() {
        var result = fusionService.fuse(rule(80), rf(0.9f));

        assertEquals(83.0, result.finalScore(), 0.0001);
        assertEquals("DANGER", result.finalRiskLevel());
    }

    @Test
    void boundaryResults() {
        assertEquals("SAFE",
                fusionService.fuse(rule(0), rf(0.99f))
                        .finalRiskLevel());

        assertEquals("WARNING",
                fusionService.fuse(rule(0), rf(1.0f))
                        .finalRiskLevel());

        assertEquals("DANGER",
                fusionService.fuse(rule(100), rf(0.0f))
                        .finalRiskLevel());
    }

    @Test
    void invalidProbabilityThrowsException() {
        assertThrows(IllegalArgumentException.class,
                () -> fusionService.fuse(rule(40), rf(1.5f)));
    }
}
