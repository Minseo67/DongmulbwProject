
package com.dongmulbw.backend.service;

import org.springframework.stereotype.Service;

@Service
public class JevTriggerService {

        private static final double DIFFERENCE_THRESHOLD = 40.0;
        private static final double UNCERTAIN_MIN = 40.0;
        private static final double UNCERTAIN_MAX = 60.0;

        /**
         * 규칙 기반 점수와 RF 악성 확률을 바탕으로
         * JEV 추가 검증이 필요한지 판단합니다.
         *
         * 조건 A: 두 점수의 차이가 40점 이상
         * 조건 B: 두 점수의 평균이 40~60점
         *
         * 둘 중 하나라도 충족하면 JEV를 실행합니다.
         *
         * @param ruleScore     규칙 기반 위험도 (0~100)
         * @param rfProbability RF 악성 확률 (0~1)
         * @return JEV 실행 필요 여부
         */
        public boolean shouldRunJev(
                        double ruleScore,
                        double rfProbability) {

                // 1. 규칙 기반 점수 유효성 검사
                if (!Double.isFinite(ruleScore)
                                || ruleScore < 0
                                || ruleScore > 100) {

                        throw new IllegalArgumentException(
                                        "규칙 기반 점수는 0~100이어야 합니다.");
                }

                // 2. RF 악성 확률 유효성 검사
                if (!Double.isFinite(rfProbability)
                                || rfProbability < 0
                                || rfProbability > 1) {

                        throw new IllegalArgumentException(
                                        "RF 확률은 0~1이어야 합니다.");
                }

                // 3. RF 확률을 0~100점으로 변환
                double rfScore = rfProbability * 100.0;

                // 4. 두 점수의 차이 계산
                double difference = Math.abs(ruleScore - rfScore);

                // 5. 임시 통합 점수 계산
                double combinedScore = (ruleScore + rfScore) / 2.0;

                // 조건 A: 두 점수 차이 40점 이상
                boolean isConflict = difference >= DIFFERENCE_THRESHOLD;

                // 조건 B: 통합 점수 40~60점
                boolean isUncertain = combinedScore >= UNCERTAIN_MIN
                                && combinedScore <= UNCERTAIN_MAX;

                // 6. 하나라도 충족하면 JEV 실행
                return isConflict || isUncertain;
        }
}
