
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.entity.Url;
import com.dongmulbw.backend.entity.UrlAnalysis;
import com.dongmulbw.backend.repository.UrlRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UrlAnalysisPrecheckService {

    private static final int HASH_KEY_VERSION = 1;

    private final UrlRepository urlRepository;
    private final UrlAnalysisCacheService cacheService;

    public UrlAnalysisPrecheckService(
            UrlRepository urlRepository,
            UrlAnalysisCacheService cacheService) {

        this.urlRepository = urlRepository;
        this.cacheService = cacheService;
    }

    /**
     * URL 분석 전 DB 조회 및 캐시 확인.
     *
     * 현재 규칙 버전과 실제 RF 모델 버전을
     * 호출하는 쪽에서 전달해야 한다.
     */
    @Transactional(readOnly = true)
    public PrecheckResult check(
            UrlNormalizationResult normalized,
            String ruleVersion,
            String modelVersion) {

        if (normalized == null) {
            throw new IllegalArgumentException(
                    "URL 정규화 결과가 필요합니다.");
        }

        validateVersion(ruleVersion, "ruleVersion");
        validateVersion(modelVersion, "modelVersion");

        // 1. 정규화된 URL의 해시로 기존 URL 조회
        Optional<Url> existingUrl = urlRepository.findByHashKeyVersionAndUrlHash(
                HASH_KEY_VERSION,
                normalized.urlHash());

        // 2. 기존 URL이 없다면 신규 분석 대상
        if (existingUrl.isEmpty()) {
            return new PrecheckResult(
                    PrecheckStatus.NEW_URL,
                    null,
                    null);
        }

        Url url = existingUrl.get();

        // 3. 해시가 같지만 URL이 다르면 오류
        if (!url.getNormalizedUrl()
                .equals(normalized.normalizedUrl())) {

            throw new IllegalStateException(
                    "URL 해시 충돌 또는 정규화 정책 불일치");
        }

        // 4. 기존 분석 결과의 유효성 확인
        Optional<UrlAnalysis> cached = cacheService.findValidAnalysis(
                url.getUrlId(),
                ruleVersion,
                modelVersion,
                normalized.normalizationVersion());

        // 5. 유효한 분석 결과가 존재하면 재사용
        if (cached.isPresent()) {
            return new PrecheckResult(
                    PrecheckStatus.CACHE_HIT,
                    url.getUrlId(),
                    cached.get());
        }

        // 6. URL은 존재하지만 분석 결과가 없거나 만료됨
        return new PrecheckResult(
                PrecheckStatus.REANALYSIS_REQUIRED,
                url.getUrlId(),
                null);
    }

    private void validateVersion(
            String version,
            String fieldName) {

        if (version == null
                || version.isBlank()
                || version.length() > 50) {

            throw new IllegalArgumentException(
                    fieldName + "은 1~50자여야 합니다.");
        }
    }

    /**
     * 사전 조회 결과 상태
     */
    public enum PrecheckStatus {
        NEW_URL,
        CACHE_HIT,
        REANALYSIS_REQUIRED
    }

    /**
     * 사전 조회 결과
     *
     * NEW_URL:
     * urlId = null
     * cachedAnalysis = null
     *
     * CACHE_HIT:
     * urlId = 기존 URL ID
     * cachedAnalysis = 유효한 분석 결과
     *
     * REANALYSIS_REQUIRED:
     * urlId = 기존 URL ID
     * cachedAnalysis = null
     */
    public record PrecheckResult(
            PrecheckStatus status,
            Long urlId,
            UrlAnalysis cachedAnalysis) {
    }
}
