
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.entity.AnalysisRun;
import com.dongmulbw.backend.entity.UrlAnalysis;
import com.dongmulbw.backend.repository.AnalysisRunRepository;
import com.dongmulbw.backend.repository.UrlAnalysisRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class UrlAnalysisPersistenceService {

    private final UrlAnalysisRepository analysisRepository;
    private final AnalysisRunRepository runRepository;

    public UrlAnalysisPersistenceService(
            UrlAnalysisRepository analysisRepository,
            AnalysisRunRepository runRepository) {

        this.analysisRepository = analysisRepository;
        this.runRepository = runRepository;
    }

    /**
     * 실제 분석 결과 저장 및 실행 완료 처리.
     *
     * 이 메서드는 규칙 기반 분석과 RF 분석이
     * 모두 완료된 이후에 호출해야 한다.
     *
     * 저장과 완료 처리는 하나의 트랜잭션으로 수행된다.
     */
    @Transactional
    public UrlAnalysis saveCompletedAnalysis(
            Long urlId,
            String runToken,
            String riskLevel,
            BigDecimal finalScore,
            BigDecimal ruleScore,
            BigDecimal rfProbability,
            String ruleFindings,
            String featuresJson,
            String ruleVersion,
            String modelVersion,
            String normalizationVersion,
            LocalDateTime analyzedAt,
            LocalDateTime expiresAt) {

        // 1. 입력값 검증
        validateInput(
                urlId,
                runToken,
                riskLevel,
                finalScore,
                ruleScore,
                rfProbability,
                ruleVersion,
                modelVersion,
                normalizationVersion,
                analyzedAt,
                expiresAt);

        // 2. 현재 분석 실행 정보 조회
        AnalysisRun run = runRepository.findByUrlId(urlId)
                .orElseThrow(() -> new IllegalStateException(
                        "분석 실행 정보가 존재하지 않습니다."));

        // 3. 실행 토큰 및 상태 확인
        if (!runToken.equals(run.getRunToken())) {
            throw new IllegalStateException(
                    "분석 실행 토큰이 일치하지 않습니다.");
        }

        if (!"PROCESSING".equals(run.getRunStatus())) {
            throw new IllegalStateException(
                    "현재 실행 중인 분석 작업이 아닙니다.");
        }

        // 4. 분석에 사용한 버전과 실행 대상 버전 확인
        if (!ruleVersion.equals(run.getTargetRuleVersion())
                || !modelVersion.equals(
                        run.getTargetModelVersion())
                || !normalizationVersion.equals(
                        run.getTargetNormalizationVersion())) {

            throw new IllegalStateException(
                    "분석 실행 대상 버전과 결과 버전이 다릅니다.");
        }

        // 5. 신규 결과 토큰 생성
        String resultToken = UUID.randomUUID().toString();

        // 6. 기존 분석 결과 확인
        Optional<UrlAnalysis> existing = analysisRepository.findByUrlId(urlId);

        UrlAnalysis analysis;

        if (existing.isPresent()) {

            // 기존 URL: 최신 분석 결과로 갱신
            analysis = existing.get();

            analysis.updateAnalysis(
                    resultToken,
                    riskLevel,
                    finalScore,
                    ruleScore,
                    rfProbability,
                    ruleFindings,
                    featuresJson,
                    ruleVersion,
                    modelVersion,
                    normalizationVersion,
                    analyzedAt,
                    expiresAt);

        } else {

            // 신규 URL: 분석 결과 생성
            analysis = new UrlAnalysis(
                    urlId,
                    resultToken,
                    riskLevel,
                    finalScore,
                    ruleScore,
                    rfProbability,
                    ruleFindings,
                    featuresJson,
                    ruleVersion,
                    modelVersion,
                    normalizationVersion,
                    analyzedAt,
                    expiresAt);
        }

        // 7. 분석 결과 DB 반영
        analysis = analysisRepository.saveAndFlush(analysis);

        // 8. 실행 토큰과 lease를 다시 검증하며 완료 처리
        int updated = runRepository.markCompleted(
                urlId,
                runToken);

        if (updated != 1) {
            // 예외 발생 시 분석 결과 저장도 ROLLBACK
            throw new IllegalStateException(
                    "분석 완료 처리에 실패했습니다. "
                            + "실행 토큰 또는 lease를 확인하세요.");
        }

        return analysis;
    }

    /**
     * 입력값 및 DB 제약조건 검증
     */
    private void validateInput(
            Long urlId,
            String runToken,
            String riskLevel,
            BigDecimal finalScore,
            BigDecimal ruleScore,
            BigDecimal rfProbability,
            String ruleVersion,
            String modelVersion,
            String normalizationVersion,
            LocalDateTime analyzedAt,
            LocalDateTime expiresAt) {

        if (urlId == null || urlId <= 0) {
            throw new IllegalArgumentException(
                    "유효한 URL ID가 필요합니다.");
        }

        if (runToken == null
                || runToken.length() != 36) {
            throw new IllegalArgumentException(
                    "유효한 실행 토큰이 필요합니다.");
        }

        try {
            UUID.fromString(runToken);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "실행 토큰은 UUID 형식이어야 합니다.");
        }

        if (!"SAFE".equals(riskLevel)
                && !"WARNING".equals(riskLevel)
                && !"DANGER".equals(riskLevel)) {
            throw new IllegalArgumentException(
                    "지원하지 않는 위험 등급입니다.");
        }

        validateScore(finalScore, "finalScore", 2);
        validateScore(ruleScore, "ruleScore", 2);

        // RF 최종 분석이 완료되지 않았다면 저장 금지
        if (rfProbability == null) {
            throw new IllegalArgumentException(
                    "RF 분석 결과가 필요합니다.");
        }

        if (rfProbability.compareTo(BigDecimal.ZERO) < 0
                || rfProbability.compareTo(BigDecimal.ONE) > 0
                || rfProbability.scale() > 6) {
            throw new IllegalArgumentException(
                    "rfProbability는 0~1 범위의 "
                            + "소수점 6자리 이하여야 합니다.");
        }

        validateVersion(ruleVersion, "ruleVersion");
        validateVersion(modelVersion, "modelVersion");
        validateVersion(
                normalizationVersion,
                "normalizationVersion");

        if (analyzedAt == null || expiresAt == null
                || !expiresAt.isAfter(analyzedAt)) {
            throw new IllegalArgumentException(
                    "분석 결과 만료시각은 "
                            + "분석시각보다 늦어야 합니다.");
        }
    }

    private void validateScore(
            BigDecimal score,
            String fieldName,
            int maxScale) {

        if (score == null
                || score.compareTo(BigDecimal.ZERO) < 0
                || score.compareTo(
                        new BigDecimal("100")) > 0
                || score.scale() > maxScale) {

            throw new IllegalArgumentException(
                    fieldName
                            + "는 0~100 범위의 "
                            + "소수점 2자리 이하여야 합니다.");
        }
    }

    private void validateVersion(
            String version,
            String fieldName) {

        if (version == null
                || version.isBlank()
                || version.length() > 50) {

            throw new IllegalArgumentException(
                    fieldName
                            + "은 1~50자여야 합니다.");
        }
    }
}
