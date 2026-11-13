
package com.dongmulbw.backend.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

@Service
public class ParallelUrlAnalysisService {

    private final UrlAnalysisService urlAnalysisService;
    private final MlAnalysisService mlAnalysisService;
    private final NeuroSymbolicFusionService fusionService;
    private final Executor executor;

    public ParallelUrlAnalysisService(
            UrlAnalysisService urlAnalysisService,
            MlAnalysisService mlAnalysisService,
            NeuroSymbolicFusionService fusionService,
            @org.springframework.beans.factory.annotation.Qualifier(
                    "analysisExecutor") Executor executor) {

        this.urlAnalysisService = urlAnalysisService;
        this.mlAnalysisService = mlAnalysisService;
        this.fusionService = fusionService;
        this.executor = executor;
    }

    public ParallelResult analyze(
            String rawUrl,
            String normalizedUrl,
            String domain) {

        // 1. 기존 규칙 기반 + DB 분석 병렬 실행
        CompletableFuture<UrlAnalysisService.AnalysisResult> ruleFuture =
                CompletableFuture.supplyAsync(
                        () -> urlAnalysisService.analyze(
                                rawUrl, normalizedUrl, domain),
                        executor
                );

        // 2. RF G 모델 병렬 실행
        CompletableFuture<MlAnalysisService.MlResult> rfFuture =
                CompletableFuture.supplyAsync(() -> {
                    try {
                        return mlAnalysisService.analyze(rawUrl);
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                }, executor);

        // 3. 두 분석이 모두 완료될 때까지 대기
        CompletableFuture.allOf(ruleFuture, rfFuture).join();

        UrlAnalysisService.AnalysisResult existingAnalysis =
                ruleFuture.join();

        MlAnalysisService.MlResult rfAnalysis =
                rfFuture.join();

        // 4. 규칙 점수 + RF 악성 확률 결합
        NeuroSymbolicFusionService.FusionResult fusionResult =
                fusionService.fuse(
                        existingAnalysis.ruleResult(),
                        rfAnalysis,
                        existingAnalysis.reputationStatus()
                );

        // 5. 기존 결과와 결합 결과 함께 반환
        return new ParallelResult(
                existingAnalysis,
                rfAnalysis,
                fusionResult
        );
    }

    public record ParallelResult(
            UrlAnalysisService.AnalysisResult existingAnalysis,
            MlAnalysisService.MlResult rfAnalysis,
            NeuroSymbolicFusionService.FusionResult fusionResult
    ) {}
}
