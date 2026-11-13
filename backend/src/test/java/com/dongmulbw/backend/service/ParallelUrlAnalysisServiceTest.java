
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class ParallelUrlAnalysisServiceTest {

    private final UrlAnalysisService urlAnalysisService =
            mock(UrlAnalysisService.class);

    private final MlAnalysisService mlAnalysisService =
            mock(MlAnalysisService.class);

    private final NeuroSymbolicFusionService fusionService =
            new NeuroSymbolicFusionService();

    // 별도 스레드에서 실행
    private final Executor executor =
            java.util.concurrent.ForkJoinPool.commonPool();

    private final ParallelUrlAnalysisService parallelService =
            new ParallelUrlAnalysisService(
                    urlAnalysisService,
                    mlAnalysisService,
                    fusionService,
                    executor
            );

    private RuleAnalysisResult rule(double score) {
        return new RuleAnalysisResult(
                0, 0, 0, 0,
                false, false, false, false,
                false, false, false,
                0, score, "WARNING",
                List.of()
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
    void parallelAnalysisReturnsFusionResult() throws Exception {

        String rawUrl = "https://example.com";
        String normalizedUrl = rawUrl;
        String domain = "example.com";

        var ruleResult = rule(40.0);

        var existingAnalysis =
                new UrlAnalysisService.AnalysisResult(
                        ruleResult,
                        null,
                        false
                );

        var rfResult = rf(0.8f);

        when(urlAnalysisService.analyze(
                rawUrl, normalizedUrl, domain))
                .thenReturn(existingAnalysis);

        when(mlAnalysisService.analyze(rawUrl))
                .thenReturn(rfResult);

        var result = parallelService.analyze(
                rawUrl, normalizedUrl, domain
        );

        // 규칙 분석 및 RF 분석 결과 유지
        assertSame(existingAnalysis, result.existingAnalysis());
        assertSame(rfResult, result.rfAnalysis());

        // 최종 결합 점수 및 등급 확인
        assertEquals(
                52.0,
                result.fusionResult().finalScore(),
                0.0001
        );

        assertEquals(
                "WARNING",
                result.fusionResult().finalRiskLevel()
        );

        // 두 분석 서비스가 각각 한 번 호출되었는지 확인
        verify(urlAnalysisService, times(1))
                .analyze(rawUrl, normalizedUrl, domain);

        verify(mlAnalysisService, times(1))
                .analyze(rawUrl);
    }

    @Test
    void rfFailurePropagates() throws Exception {

        when(urlAnalysisService.analyze(
                anyString(), anyString(), anyString()))
                .thenReturn(
                        new UrlAnalysisService.AnalysisResult(
                                rule(40.0), null, false
                        )
                );

        when(mlAnalysisService.analyze(anyString()))
                .thenThrow(new RuntimeException("RF test failure"));

        assertThrows(
                CompletionException.class,
                () -> parallelService.analyze(
                        "https://example.com",
                        "https://example.com",
                        "example.com"
                )
        );
    }
}
