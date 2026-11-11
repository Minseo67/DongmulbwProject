
package com.dongmulbw.backend.service;

import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class JevConditionalAnalysisService {

    private final JevTriggerService jevTriggerService;
    private final JevAnalysisService jevAnalysisService;

    public JevConditionalAnalysisService(
            JevTriggerService jevTriggerService,
            JevAnalysisService jevAnalysisService) {

        this.jevTriggerService = jevTriggerService;
        this.jevAnalysisService = jevAnalysisService;
    }

    public Map<String, Object> analyze(
            String url,
            double ruleScore,
            double rfProbability) {

        // 1. JEV 실행 조건 판단
        boolean shouldRun = jevTriggerService.shouldRunJev(
                ruleScore, rfProbability);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("jevTriggered", shouldRun);

        // 2. JEV 실행 조건을 충족하지 않은 경우
        if (!shouldRun) {
            result.put("status", "SKIPPED");
            result.put("jevAnalysis", null);
            return result;
        }

        // 3. JEV 분석 시작
        long startTime = System.nanoTime();

        try {
            Map<String, Object> jevResult =
                    jevAnalysisService.analyze(url);

            // 4. JEV 응답 유효성 검사
            if (jevResult == null || jevResult.isEmpty()) {
                result.put("status", "UNAVAILABLE");
                result.put("jevAnalysis", null);
                return result;
            }

            // 5. JEV 분석 성공
            result.put("status", "COMPLETED");
            result.put("jevAnalysis", jevResult);

        } catch (RuntimeException e) {

            // 6. JEV 호출 실패 시 전체 분석 흐름 유지
            result.put("status", "UNAVAILABLE");
            result.put("jevAnalysis", null);

            System.err.println(
                    "[JEV] 분석 요청 실패: "
                    + e.getClass().getSimpleName()
            );

        } finally {

            // 7. JEV 분석 소요 시간 기록
            long elapsedMs =
                    (System.nanoTime() - startTime) / 1_000_000;

            result.put("elapsedMs", elapsedMs);
        }

        return result;
    }
}
