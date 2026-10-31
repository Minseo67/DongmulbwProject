
package com.dongmulbw.backend.repository;

import com.dongmulbw.backend.entity.Url;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UrlRepository extends JpaRepository<Url, Long> {

    // 정규화 URL의 해시를 이용한 중복 조회
    Optional<Url> findByHashKeyVersionAndUrlHash(
            Integer hashKeyVersion,
            String urlHash);

    // 기존 URL이 수집되면 횟수와 마지막 수집 시각 갱신
    @Modifying
    @Query(value = """
            UPDATE urls
            SET seen_count = seen_count + 1,
                last_seen_at = CURRENT_TIMESTAMP(3)
            WHERE hash_key_version = :hashKeyVersion
              AND url_hash = :urlHash
            """, nativeQuery = true)
    int incrementSeenCount(
            @Param("hashKeyVersion") Integer hashKeyVersion,
            @Param("urlHash") String urlHash);

    @Modifying
    @Query(value = """
            INSERT INTO urls (
                url_hash,
                hash_key_version,
                normalized_url,
                original_url,
                normalization_version,
                domain,
                scheme
            )
            VALUES (
                :urlHash,
                :hashKeyVersion,
                :normalizedUrl,
                :originalUrl,
                :normalizationVersion,
                :domain,
                :scheme
            )
            ON DUPLICATE KEY UPDATE
                seen_count = seen_count + 1,
                last_seen_at = CURRENT_TIMESTAMP(3)
            """, nativeQuery = true)
    int upsertUrl(
            @Param("urlHash") String urlHash,
            @Param("hashKeyVersion") Integer hashKeyVersion,
            @Param("normalizedUrl") String normalizedUrl,
            @Param("originalUrl") String originalUrl,
            @Param("normalizationVersion") String normalizationVersion,
            @Param("domain") String domain,
            @Param("scheme") String scheme);

}
