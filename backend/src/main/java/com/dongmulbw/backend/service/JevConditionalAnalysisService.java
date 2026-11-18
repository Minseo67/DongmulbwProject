
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

    /**
     * 점수 기반 조건에 따라 JEV를 실행하거나 생략합니다.
     *
     * @param url           분석할 URL
     * @param ruleScore     규칙 기반 점수 (0~100)
     * @param rfProbability RF 악성 확률 (0~1)
     */
    public Map<String, Object> analyze(
            String url,
            double ruleScore,
            double rfProbability) {

        // 1. JEV 실행 조건 확인
        boolean shouldRun = jevTriggerService.shouldRunJev(
                ruleScore,
                rfProbability);

        Map<String, Object> result = new LinkedHashMap<>();

        result.put("jevTriggered", shouldRun);

        // 2. 실행 조건 미충족: JEV 생략
        if (!shouldRun) {

            result.put("status", "SKIPPED");
            result.put(
                    "skipReason",
                    "SCORE_CONDITIONS_NOT_MET");
            result.put("jevAnalysis", null);
            result.put("elapsedMs", null);

            return result;
        }

        // 3. JEV 분석 시작
        long startTime = System.nanoTime();

        try {

            Map<String, Object> analysis = jevAnalysisService.analyze(url);

            // 4. 응답이 없거나 비어 있는 경우
            if (analysis == null || analysis.isEmpty()) {

                result.put("status", "UNAVAILABLE");
                result.put("jevAnalysis", null);

            } else {

                // 5. JEV 응답 수신
                result.put("status", "COMPLETED");
                result.put("jevAnalysis", analysis);
            }

        } catch (RuntimeException e) {

            // 6. JEV 오류가 발생해도
            // 전체 URL 분석은 계속 진행
            result.put("status", "UNAVAILABLE");
            result.put("jevAnalysis", null);

            System.err.println(
                    "[JEV] 분석 요청 실패: "
                            + e.getClass().getSimpleName());

        } finally {

            // 7. JEV 소요 시간 기록
            long elapsedMs = (System.nanoTime() - startTime) / 1_000_000;

            result.put("elapsedMs", elapsedMs);
        }

        return result;
    }
}
