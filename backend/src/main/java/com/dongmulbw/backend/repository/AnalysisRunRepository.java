
package com.dongmulbw.backend.repository;

import com.dongmulbw.backend.entity.AnalysisRun;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface AnalysisRunRepository
        extends JpaRepository<AnalysisRun, Long> {

    // URL ID로 분석 작업 조회
    Optional<AnalysisRun> findByUrlId(Long urlId);

    // 실행 토큰으로 분석 작업 조회
    Optional<AnalysisRun> findByRunToken(String runToken);

    // 분석 작업 존재 여부 확인
    boolean existsByUrlId(Long urlId);

    /**
     * 최초 분석 작업 생성.
     *
     * 해당 URL의 작업이 없으면 INSERT.
     * 이미 존재하면 기존 데이터를 변경하지 않는다.
     */
    @Modifying
    @Query(value = """
            INSERT INTO analysis_runs (
                url_id,
                run_token,
                run_status,
                target_rule_version,
                target_model_version,
                target_normalization_version,
                processing_started_at,
                lease_expires_at,
                attempt_count
            )
            VALUES (
                :urlId,
                :runToken,
                'PROCESSING',
                :ruleVersion,
                :modelVersion,
                :normalizationVersion,
                CURRENT_TIMESTAMP(3),
                TIMESTAMPADD(
                    SECOND,
                    :leaseSeconds,
                    CURRENT_TIMESTAMP(3)
                ),
                1
            )
            ON DUPLICATE KEY UPDATE
                run_id = run_id
            """, nativeQuery = true)
    int insertIfAbsent(
            @Param("urlId") Long urlId,
            @Param("runToken") String runToken,
            @Param("ruleVersion") String ruleVersion,
            @Param("modelVersion") String modelVersion,
            @Param("normalizationVersion") String normalizationVersion,
            @Param("leaseSeconds") int leaseSeconds);

    /**
     * 기존 분석 작업의 실행 권한 획득.
     *
     * PROCESSING:
     * lease가 만료된 경우에만 재획득
     *
     * FAILED:
     * retry_after가 지났거나 NULL이면 재획득
     *
     * COMPLETED:
     * 현재 버전에 맞는 유효한 분석 캐시가
     * 존재하지 않는 경우에만 재획득
     *
     * 조건부 UPDATE로 중복 실행을 방지한다.
     */
    @Modifying
    @Query(value = """
            UPDATE analysis_runs
            SET
                run_token = :runToken,
                run_status = 'PROCESSING',
                target_rule_version = :ruleVersion,
                target_model_version = :modelVersion,
                target_normalization_version =
                    :normalizationVersion,
                processing_started_at =
                    CURRENT_TIMESTAMP(3),
                lease_expires_at = TIMESTAMPADD(
                    SECOND,
                    :leaseSeconds,
                    CURRENT_TIMESTAMP(3)
                ),
                finished_at = NULL,
                retry_after = NULL,
                error_code = NULL,
                attempt_count = attempt_count + 1
            WHERE url_id = :urlId
              AND attempt_count < 65535
              AND (
                  (
                      run_status = 'PROCESSING'
                      AND lease_expires_at <=
                          CURRENT_TIMESTAMP(3)
                  )
                  OR (
                      run_status = 'FAILED'
                      AND (
                          retry_after IS NULL
                          OR retry_after <=
                              CURRENT_TIMESTAMP(3)
                      )
                  )
                  OR (
                      run_status = 'COMPLETED'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM url_analysis ua
                          WHERE ua.url_id = :urlId
                            AND ua.expires_at >
                                CURRENT_TIMESTAMP(3)
                            AND ua.rule_version =
                                :ruleVersion
                            AND ua.model_version =
                                :modelVersion
                            AND ua.normalization_version =
                                :normalizationVersion
                      )
                  )
              )
            """, nativeQuery = true)
    int acquireExistingRun(
            @Param("urlId") Long urlId,
            @Param("runToken") String runToken,
            @Param("ruleVersion") String ruleVersion,
            @Param("modelVersion") String modelVersion,
            @Param("normalizationVersion") String normalizationVersion,
            @Param("leaseSeconds") int leaseSeconds);

    /**
     * 분석 완료 처리.
     *
     * 실행 토큰이 일치하고,
     * PROCESSING 상태이며,
     * lease가 유효한 경우에만 완료 처리한다.
     */
    @Modifying
    @Query(value = """
            UPDATE analysis_runs
            SET
                run_status = 'COMPLETED',
                finished_at = CURRENT_TIMESTAMP(3),
                retry_after = NULL,
                error_code = NULL
            WHERE url_id = :urlId
              AND run_token = :runToken
              AND run_status = 'PROCESSING'
              AND lease_expires_at >
                  CURRENT_TIMESTAMP(3)
            """, nativeQuery = true)
    int markCompleted(
            @Param("urlId") Long urlId,
            @Param("runToken") String runToken);

    /**
     * 분석 실패 처리.
     *
     * 현재 실행 토큰이 일치하고
     * lease가 유효할 때만 실패 처리한다.
     *
     * retrySeconds 이후 재시도가 가능하다.
     */
    @Modifying
    @Query(value = """
            UPDATE analysis_runs
            SET
                run_status = 'FAILED',
                finished_at = CURRENT_TIMESTAMP(3),
                error_code = :errorCode,
                retry_after = TIMESTAMPADD(
                    SECOND,
                    :retrySeconds,
                    CURRENT_TIMESTAMP(3)
                )
            WHERE url_id = :urlId
              AND run_token = :runToken
              AND run_status = 'PROCESSING'
              AND lease_expires_at >
                  CURRENT_TIMESTAMP(3)
            """, nativeQuery = true)
    int markFailed(
            @Param("urlId") Long urlId,
            @Param("runToken") String runToken,
            @Param("errorCode") String errorCode,
            @Param("retrySeconds") int retrySeconds);
}
