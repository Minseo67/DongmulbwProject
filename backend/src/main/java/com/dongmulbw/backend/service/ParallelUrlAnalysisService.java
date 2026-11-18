
package com.dongmulbw.backend.service;

import org.springframework.beans.factory.annotation.Qualifier;
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
                        @Qualifier("analysisExecutor") Executor executor) {

                this.urlAnalysisService = urlAnalysisService;
                this.mlAnalysisService = mlAnalysisService;
                this.fusionService = fusionService;
                this.executor = executor;
        }

        public ParallelResult analyze(
                        String rawUrl,
                        String normalizedUrl,
                        String domain) {

                // 1. RF 실행: 블랙리스트 여부와 관계없이 실행
                CompletableFuture<MlAnalysisService.MlResult> rfFuture = CompletableFuture.supplyAsync(() -> {
                        try {
                                return mlAnalysisService.analyze(rawUrl);
                        } catch (Exception e) {
                                throw new CompletionException(e);
                        }
                }, executor);

                // 2. 규칙 기반 분석 및 평판 조회
                // 블랙리스트는 UrlAnalysisService에서 규칙 점수 100점
                UrlAnalysisService.AnalysisResult ruleAnalysis;

                try {
                        ruleAnalysis = urlAnalysisService.analyze(
                                        rawUrl, normalizedUrl, domain);
                } catch (RuntimeException e) {
                        rfFuture.cancel(true);
                        throw e;
                }

                // 3. RF 결과 수집
                MlAnalysisService.MlResult rfAnalysis;

                try {
                        rfAnalysis = rfFuture.join();

                        if (rfAnalysis == null) {
                                throw new IllegalStateException(
                                                "RF 분석 결과가 null입니다.");
                        }

                } catch (CompletionException | IllegalStateException e) {

                        // RF 실패 시 규칙 점수만 사용
                        return new ParallelResult(
                                        ruleAnalysis,
                                        null,
                                        fallbackFusion(ruleAnalysis),
                                        "UNAVAILABLE");
                }

                // 4. 규칙 70% + RF 30% 계산
                NeuroSymbolicFusionService.FusionResult fusion = fusionService.fuse(
                                ruleAnalysis.ruleResult(),
                                rfAnalysis,
                                ruleAnalysis.reputationStatus());

                return new ParallelResult(
                                ruleAnalysis,
                                rfAnalysis,
                                fusion,
                                "SUCCESS");
        }

        private NeuroSymbolicFusionService.FusionResult fallbackFusion(
                        UrlAnalysisService.AnalysisResult analysis) {

                double score = analysis.ruleResult().suspiciousScore();

                String level = score >= 60.0 ? "DANGER"
                                : score >= 30.0 ? "WARNING"
                                                : "SAFE";

                return new NeuroSymbolicFusionService.FusionResult(
                                score,
                                0.0,
                                score,
                                level);
        }

        public record ParallelResult(
                        UrlAnalysisService.AnalysisResult existingAnalysis,
                        MlAnalysisService.MlResult rfAnalysis,
                        NeuroSymbolicFusionService.FusionResult fusionResult,
                        String rfStatus) {
        }
}
