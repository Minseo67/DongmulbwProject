
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.UrlNormalizationResult;
import com.dongmulbw.backend.entity.Url;
import com.dongmulbw.backend.repository.UrlRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UrlStorageService {

    private static final int HASH_KEY_VERSION = 1;

    private final UrlRepository urlRepository;

    public UrlStorageService(UrlRepository urlRepository) {
        this.urlRepository = urlRepository;
    }

    @Transactional
    public Url saveOrUpdate(UrlNormalizationResult result) {

        // 1. 기존 DB의 UNIQUE 키를 이용해 저장 또는 갱신
        urlRepository.upsertUrl(
                result.urlHash(),
                HASH_KEY_VERSION,
                result.normalizedUrl(),
                result.rawUrl(),
                result.normalizationVersion(),
                result.domain(),
                result.scheme());

        // 2. 저장된 URL을 다시 조회
        Url savedUrl = urlRepository
                .findByHashKeyVersionAndUrlHash(
                        HASH_KEY_VERSION,
                        result.urlHash())
                .orElseThrow(() -> new IllegalStateException(
                        "URL 저장 후 조회 실패"));

        // 3. 해시 키가 같아도 정규화 URL이 다르면 오류 처리
        if (!savedUrl.getNormalizedUrl()
                .equals(result.normalizedUrl())) {
            throw new IllegalStateException(
                    "URL 해시 충돌 또는 정규화 정책 불일치");
        }

        return savedUrl;
    }
}
