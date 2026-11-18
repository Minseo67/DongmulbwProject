
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JevTriggerServiceTest {

    private final JevTriggerService service =
            new JevTriggerService();

    // 조건 A: 점수 차이가 정확히 40점이면 실행
    @Test
    void differenceOfFortyTriggers() {

        assertTrue(
                service.shouldRunJev(10, .50)
        );
    }

    // 조건 B: 평균 점수가 40~60점이면 실행
    @Test
    void averageBetweenFortyAndSixtyTriggers() {

        assertTrue(
                service.shouldRunJev(45, .55)
        );
    }

    // 두 조건을 모두 충족하지 않으면 생략
    @Test
    void neitherConditionSkips() {

        assertFalse(
                service.shouldRunJev(10, .20)
        );
    }

    // 등급이 같더라도 평균 점수가 모호하면 실행
    @Test
    void sameRiskGradeCanStillTriggerByScore() {

        assertTrue(
                service.shouldRunJev(45, .45)
        );
    }

    // 규칙 기반 점수 범위 오류
    @Test
    void invalidScoreRejected() {

        assertThrows(
                IllegalArgumentException.class,
                () -> service.shouldRunJev(101, .20)
        );
    }
}
