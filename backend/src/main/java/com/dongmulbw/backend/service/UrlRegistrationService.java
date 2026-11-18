
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.entity.Url;
import com.dongmulbw.backend.repository.UrlRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UrlRegistrationService {

    private static final int HASH_KEY_VERSION = 1;

    private final UrlRepository urlRepository;

    public UrlRegistrationService(UrlRepository urlRepository) {
        this.urlRepository = urlRepository;
    }

    @Transactional
    public RegistrationResult register(UrlNormalizationResult normalized) {

        boolean existed = urlRepository
                .findByHashKeyVersionAndUrlHash(
                        HASH_KEY_VERSION, normalized.urlHash())
                .isPresent();

        urlRepository.upsertUrl(
                normalized.urlHash(),
                HASH_KEY_VERSION,
                normalized.normalizedUrl(),
                normalized.rawUrl(),
                normalized.normalizationVersion(),
                normalized.domain(),
                normalized.scheme());

        Url saved = urlRepository
                .findByHashKeyVersionAndUrlHash(
                        HASH_KEY_VERSION, normalized.urlHash())
                .orElseThrow(() -> new IllegalStateException(
                        "URL 등록 후 조회에 실패했습니다."));

        if (!saved.getNormalizedUrl().equals(
                normalized.normalizedUrl())) {
            throw new IllegalStateException(
                    "URL 해시 충돌 또는 정규화 결과 불일치");
        }

        return new RegistrationResult(
                saved.getUrlId(), existed);
    }

    public record RegistrationResult(
            Long urlId,
            boolean urlExists) {
    }
}
