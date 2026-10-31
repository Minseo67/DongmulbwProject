
package com.dongmulbw.backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "urls", uniqueConstraints = {
        @UniqueConstraint(name = "uk_urls_hash", columnNames = { "hash_key_version", "url_hash" })
}, indexes = {
        @Index(name = "idx_urls_domain", columnList = "domain"),
        @Index(name = "idx_urls_last_seen", columnList = "last_seen_at")
})
public class Url {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "url_id", nullable = false, columnDefinition = "BIGINT UNSIGNED")
    private Long urlId;

    @Column(name = "url_hash", nullable = false, length = 64, columnDefinition = "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin")
    private String urlHash;

    @Column(name = "hash_key_version", nullable = false, columnDefinition = "SMALLINT UNSIGNED DEFAULT 1")
    private Integer hashKeyVersion = 1;

    @Column(name = "normalized_url", nullable = false, length = 2048, columnDefinition = "VARCHAR(2048) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
    private String normalizedUrl;

    @Column(name = "original_url", length = 2048)
    private String originalUrl;

    @Column(name = "normalization_version", nullable = false, length = 50)
    private String normalizationVersion;

    @Column(name = "domain", nullable = false, length = 253)
    private String domain;

    @Column(name = "scheme", nullable = false, length = 5)
    private String scheme;

    @Column(name = "first_seen_at", nullable = false, insertable = false, updatable = false, columnDefinition = "DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)")
    private LocalDateTime firstSeenAt;

    @Column(name = "last_seen_at", nullable = false, insertable = false, updatable = false, columnDefinition = "DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)")
    private LocalDateTime lastSeenAt;

    @Column(name = "seen_count", nullable = false, insertable = false, updatable = false, columnDefinition = "BIGINT UNSIGNED DEFAULT 1")
    private Long seenCount;

    protected Url() {
        // JPA에서 사용하는 기본 생성자
    }

    public Url(
            String urlHash,
            Integer hashKeyVersion,
            String normalizedUrl,
            String originalUrl,
            String normalizationVersion,
            String domain,
            String scheme) {
        this.urlHash = urlHash;
        this.hashKeyVersion = hashKeyVersion;
        this.normalizedUrl = normalizedUrl;
        this.originalUrl = originalUrl;
        this.normalizationVersion = normalizationVersion;
        this.domain = domain;
        this.scheme = scheme;
    }

    public Long getUrlId() {
        return urlId;
    }

    public String getUrlHash() {
        return urlHash;
    }

    public Integer getHashKeyVersion() {
        return hashKeyVersion;
    }

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public String getOriginalUrl() {
        return originalUrl;
    }

    public String getNormalizationVersion() {
        return normalizationVersion;
    }

    public String getDomain() {
        return domain;
    }

    public String getScheme() {
        return scheme;
    }

    public LocalDateTime getFirstSeenAt() {
        return firstSeenAt;
    }

    public LocalDateTime getLastSeenAt() {
        return lastSeenAt;
    }

    public Long getSeenCount() {
        return seenCount;
    }
}
