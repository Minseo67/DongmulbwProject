
package com.dongmulbw.backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "domain_reputation")
public class DomainReputation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "reputation_id", nullable = false, columnDefinition = "BIGINT UNSIGNED")
    private Long reputationId;

    @Column(name = "domain", nullable = false, unique = true, length = 253)
    private String domain;

    @Column(name = "trust_score", columnDefinition = "TINYINT UNSIGNED")
    private Integer trustScore;

    @Column(name = "is_whitelisted", nullable = false)
    private Boolean whitelisted;

    @Column(name = "is_blacklisted", nullable = false)
    private Boolean blacklisted;

    @Column(name = "source_name", length = 100)
    private String sourceName;

    @Column(name = "reason", length = 255)
    private String reason;

    @Column(name = "checked_at", columnDefinition = "DATETIME(3)")
    private LocalDateTime checkedAt;

    @Column(name = "expires_at", columnDefinition = "DATETIME(3)")
    private LocalDateTime expiresAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private LocalDateTime updatedAt;

    protected DomainReputation() {
        // JPA 기본 생성자
    }

    public Long getReputationId() {
        return reputationId;
    }

    public String getDomain() {
        return domain;
    }

    public Integer getTrustScore() {
        return trustScore;
    }

    public Boolean getWhitelisted() {
        return whitelisted;
    }

    public Boolean getBlacklisted() {
        return blacklisted;
    }

    public String getSourceName() {
        return sourceName;
    }

    public String getReason() {
        return reason;
    }

    public LocalDateTime getCheckedAt() {
        return checkedAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }
}
