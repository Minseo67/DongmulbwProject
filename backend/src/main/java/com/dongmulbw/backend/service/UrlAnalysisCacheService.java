
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.entity.UrlAnalysis;
import com.dongmulbw.backend.repository.UrlAnalysisRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class UrlAnalysisCacheService {

    private final UrlAnalysisRepository analysisRepository;

    public UrlAnalysisCacheService(
            UrlAnalysisRepository analysisRepository) {

        this.analysisRepository = analysisRepository;
    }

    /**
     * URL에 저장된 기존 분석 결과를 조회하고,
     * 현재 버전 및 유효기간을 기준으로 재사용 가능 여부를 판단한다.
     *
     * @param urlId                URL 테이블의 기본키
     * @param ruleVersion          현재 규칙 분석 버전
     * @param modelVersion         현재 RF 모델 버전
     * @param normalizationVersion 현재 URL 정규화 버전
     * @return 유효한 분석 결과가 있으면 Optional에 반환
     */
    @Transactional(readOnly = true)
    public Optional<UrlAnalysis> findValidAnalysis(
            Long urlId,
            String ruleVersion,
            String modelVersion,
            String normalizationVersion) {

        if (urlId == null
                || isBlank(ruleVersion)
                || isBlank(modelVersion)
                || isBlank(normalizationVersion)) {
            return Optional.empty();
        }

        Optional<UrlAnalysis> existing = analysisRepository.findByUrlId(urlId);

        if (existing.isEmpty()) {
            return Optional.empty();
        }

        UrlAnalysis analysis = existing.get();

        // 1. 분석 결과 만료 여부 확인
        LocalDateTime now = LocalDateTime.now();

        if (analysis.getExpiresAt() == null
                || !analysis.getExpiresAt().isAfter(now)) {
            return Optional.empty();
        }

        // 2. 규칙 기반 분석 버전 확인
        if (!ruleVersion.equals(analysis.getRuleVersion())) {
            return Optional.empty();
        }

        // 3. RF 모델 버전 확인
        if (!modelVersion.equals(analysis.getModelVersion())) {
            return Optional.empty();
        }

        // 4. URL 정규화 버전 확인
        if (!normalizationVersion.equals(
                analysis.getNormalizationVersion())) {
            return Optional.empty();
        }

        // 모든 조건을 만족하면 기존 분석 결과 반환
        return Optional.of(analysis);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
