
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.entity.AnalysisRun;
import com.dongmulbw.backend.repository.AnalysisRunRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class AnalysisRunExecutionService {

    private static final int MAX_VERSION_LENGTH = 50;
    private static final int MAX_ERROR_CODE_LENGTH = 60;

    private final AnalysisRunRepository runRepository;

    public AnalysisRunExecutionService(
            AnalysisRunRepository runRepository) {
        this.runRepository = runRepository;
    }

    /**
     * 분석 실행 권한 획득.
     *
     * 호출 전에 기존 url_analysis 캐시가
     * 유효하지 않다는 사실을 확인해야 한다.
     *
     * 반환값:
     * Optional에 토큰 존재 = 실행 권한 획득
     * Optional.empty() = 다른 작업 진행 중이거나
     * 재시도 대기 또는 획득 불가
     */
    @Transactional
    public Optional<String> acquireRun(
            Long urlId,
            String ruleVersion,
            String modelVersion,
            String normalizationVersion,
            int leaseSeconds) {

        validateUrlId(urlId);
        validateVersion(ruleVersion, "ruleVersion");
        validateVersion(modelVersion, "modelVersion");
        validateVersion(
                normalizationVersion,
                "normalizationVersion");

        if (leaseSeconds <= 0) {
            throw new IllegalArgumentException(
                    "leaseSeconds는 1 이상이어야 합니다.");
        }

        String runToken = UUID.randomUUID().toString();

        // 1. 신규 URL이면 작업 행 생성 시도
        runRepository.insertIfAbsent(
                urlId,
                runToken,
                ruleVersion,
                modelVersion,
                normalizationVersion,
                leaseSeconds);

        // 2. 방금 생성한 작업인지 토큰으로 확인
        Optional<AnalysisRun> existing = runRepository.findByUrlId(urlId);

        if (existing.isEmpty()) {
            throw new IllegalStateException(
                    "분석 작업 생성 후 조회에 실패했습니다.");
        }

        if (runToken.equals(existing.get().getRunToken())) {
            return Optional.of(runToken);
        }

        // 3. 기존 작업의 실행 권한 재획득 시도
        int updated = runRepository.acquireExistingRun(
                urlId,
                runToken,
                ruleVersion,
                modelVersion,
                normalizationVersion,
                leaseSeconds);

        if (updated == 1) {
            return Optional.of(runToken);
        }

        // 이미 실행 중이거나 재시도 제한 중
        return Optional.empty();
    }

    /**
     * 분석 완료 처리.
     *
     * 해당 실행의 토큰이 일치하고
     * lease가 유효할 때만 성공한다.
     */
    @Transactional
    public boolean completeRun(
            Long urlId,
            String runToken) {

        validateUrlId(urlId);
        validateRunToken(runToken);

        return runRepository.markCompleted(
                urlId,
                runToken) == 1;
    }

    /**
     * 분석 실패 처리 및 재시도 대기시간 설정.
     */
    @Transactional
    public boolean failRun(
            Long urlId,
            String runToken,
            String errorCode,
            int retrySeconds) {

        validateUrlId(urlId);
        validateRunToken(runToken);

        if (errorCode == null
                || errorCode.isBlank()
                || errorCode.length() > MAX_ERROR_CODE_LENGTH) {
            throw new IllegalArgumentException(
                    "errorCode는 1~60자여야 합니다.");
        }

        if (retrySeconds < 0) {
            throw new IllegalArgumentException(
                    "retrySeconds는 0 이상이어야 합니다.");
        }

        return runRepository.markFailed(
                urlId,
                runToken,
                errorCode,
                retrySeconds) == 1;
    }

    /**
     * 현재 분석 작업 조회.
     */
    @Transactional(readOnly = true)
    public Optional<AnalysisRun> findRun(Long urlId) {
        validateUrlId(urlId);
        return runRepository.findByUrlId(urlId);
    }

    private void validateUrlId(Long urlId) {
        if (urlId == null || urlId <= 0) {
            throw new IllegalArgumentException(
                    "유효한 urlId가 필요합니다.");
        }
    }

    private void validateVersion(
            String version,
            String fieldName) {

        if (version == null
                || version.isBlank()
                || version.length() > MAX_VERSION_LENGTH) {
            throw new IllegalArgumentException(
                    fieldName + "은 1~50자여야 합니다.");
        }
    }

    private void validateRunToken(String runToken) {
        if (runToken == null
                || runToken.isBlank()
                || !isValidUuid(runToken)) {
            throw new IllegalArgumentException(
                    "유효한 runToken이 필요합니다.");
        }
    }

    private boolean isValidUuid(String value) {
        try {
            UUID.fromString(value);
            return value.length() == 36;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
