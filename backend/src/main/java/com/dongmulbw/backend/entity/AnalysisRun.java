
package com.dongmulbw.backend.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "analysis_runs", uniqueConstraints = {
        @UniqueConstraint(name = "uk_runs_url", columnNames = { "url_id" }),
        @UniqueConstraint(name = "uk_runs_token", columnNames = { "run_token" })
}, indexes = {
        @Index(name = "idx_runs_status_lease", columnList = "run_status, lease_expires_at"),
        @Index(name = "idx_runs_retry", columnList = "run_status, retry_after")
})
public class AnalysisRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "run_id", nullable = false, columnDefinition = "BIGINT UNSIGNED")
    private Long runId;

    @Column(name = "url_id", nullable = false, unique = true, columnDefinition = "BIGINT UNSIGNED")
    private Long urlId;

    @Column(name = "run_token", nullable = false, length = 36, columnDefinition = "CHAR(36) CHARACTER SET ascii COLLATE ascii_bin")
    private String runToken;

    @Column(name = "run_status", nullable = false, length = 16)
    private String runStatus = "PROCESSING";

    @Column(name = "target_rule_version", nullable = false, length = 50)
    private String targetRuleVersion;

    @Column(name = "target_model_version", nullable = false, length = 50)
    private String targetModelVersion;

    @Column(name = "target_normalization_version", nullable = false, length = 50)
    private String targetNormalizationVersion;

    @Column(name = "processing_started_at", nullable = false, columnDefinition = "DATETIME(3)")
    private LocalDateTime processingStartedAt;

    @Column(name = "lease_expires_at", nullable = false, columnDefinition = "DATETIME(3)")
    private LocalDateTime leaseExpiresAt;

    @Column(name = "finished_at", columnDefinition = "DATETIME(3)")
    private LocalDateTime finishedAt;

    @Column(name = "attempt_count", nullable = false, columnDefinition = "SMALLINT UNSIGNED DEFAULT 0")
    private Integer attemptCount = 0;

    @Column(name = "retry_after", columnDefinition = "DATETIME(3)")
    private LocalDateTime retryAfter;

    @Column(name = "error_code", length = 60)
    private String errorCode;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false, columnDefinition = "DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)")
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false, columnDefinition = "DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)")
    private LocalDateTime updatedAt;

    protected AnalysisRun() {
        // JPA 기본 생성자
    }

    public Long getRunId() {
        return runId;
    }

    public Long getUrlId() {
        return urlId;
    }

    public String getRunToken() {
        return runToken;
    }

    public String getRunStatus() {
        return runStatus;
    }

    public String getTargetRuleVersion() {
        return targetRuleVersion;
    }

    public String getTargetModelVersion() {
        return targetModelVersion;
    }

    public String getTargetNormalizationVersion() {
        return targetNormalizationVersion;
    }

    public LocalDateTime getProcessingStartedAt() {
        return processingStartedAt;
    }

    public LocalDateTime getLeaseExpiresAt() {
        return leaseExpiresAt;
    }

    public LocalDateTime getFinishedAt() {
        return finishedAt;
    }

    public Integer getAttemptCount() {
        return attemptCount;
    }

    public LocalDateTime getRetryAfter() {
        return retryAfter;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }
}
