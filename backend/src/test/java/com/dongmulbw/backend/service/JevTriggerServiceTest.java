
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JevTriggerServiceTest {

    private final JevTriggerService service =
            new JevTriggerService();

    @Test
    void testLargeDifference() {
        // 규칙 85점, RF 15% → 차이 70점
        assertTrue(service.shouldRunJev(85, 0.15));
    }

    @Test
    void testUncertainScore() {
        // 통합 점수 50점 → 불확실 구간
        assertTrue(service.shouldRunJev(50, 0.50));
    }

    @Test
    void testSafeAgreement() {
        // 둘 다 안전 판단 → JEV 생략
        assertFalse(service.shouldRunJev(10, 0.10));
    }

    @Test
    void testDangerAgreement() {
        // 둘 다 위험 판단 → JEV 생략
        assertFalse(service.shouldRunJev(90, 0.90));
    }

    @Test
    void testInvalidProbability() {
        // RF 확률 범위 초과 → 예외 발생
        assertThrows(IllegalArgumentException.class,
                () -> service.shouldRunJev(50, 1.5));
    }
}
