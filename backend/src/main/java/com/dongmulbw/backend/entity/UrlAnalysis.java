
package com.dongmulbw.backend.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "url_analysis", uniqueConstraints = {
        @UniqueConstraint(name = "uk_analysis_url", columnNames = "url_id"),
        @UniqueConstraint(name = "uk_analysis_result_token", columnNames = "result_token")
}, indexes = {
        @Index(name = "idx_analysis_expires", columnList = "expires_at"),
        @Index(name = "idx_analysis_risk", columnList = "risk_level")
})
public class UrlAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "analysis_id", nullable = false, columnDefinition = "BIGINT UNSIGNED")
    private Long analysisId;

    @Column(name = "url_id", nullable = false, unique = true, columnDefinition = "BIGINT UNSIGNED")
    private Long urlId;

    @Column(name = "result_token", nullable = false, length = 36, columnDefinition = "CHAR(36) CHARACTER SET ascii COLLATE ascii_bin")
    private String resultToken;

    @Column(name = "risk_level", nullable = false, length = 10)
    private String riskLevel;

    @Column(name = "final_score", nullable = false, precision = 5, scale = 2)
    private BigDecimal finalScore;

    @Column(name = "rule_score", precision = 5, scale = 2)
    private BigDecimal ruleScore;

    @Column(name = "rf_probability", precision = 7, scale = 6)
    private BigDecimal rfProbability;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "rule_findings", columnDefinition = "json")
    private String ruleFindings;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "features_json", columnDefinition = "json")
    private String featuresJson;

    @Column(name = "rule_version", nullable = false, length = 50)
    private String ruleVersion;

    @Column(name = "model_version", nullable = false, length = 50)
    private String modelVersion;

    @Column(name = "normalization_version", nullable = false, length = 50)
    private String normalizationVersion;

    @Column(name = "analyzed_at", nullable = false, columnDefinition = "DATETIME(3)")
    private LocalDateTime analyzedAt;

    @Column(name = "expires_at", nullable = false, columnDefinition = "DATETIME(3)")
    private LocalDateTime expiresAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false, columnDefinition = "DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)")
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false, columnDefinition = "DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)")
    private LocalDateTime updatedAt;

    protected UrlAnalysis() {
        // JPA 기본 생성자
    }

    public Long getAnalysisId() {
        return analysisId;
    }

    public Long getUrlId() {
        return urlId;
    }

    public String getResultToken() {
        return resultToken;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public BigDecimal getFinalScore() {
        return finalScore;
    }

    public BigDecimal getRuleScore() {
        return ruleScore;
    }

    public BigDecimal getRfProbability() {
        return rfProbability;
    }

    public String getRuleFindings() {
        return ruleFindings;
    }

    public String getFeaturesJson() {
        return featuresJson;
    }

    public String getRuleVersion() {
        return ruleVersion;
    }

    public String getModelVersion() {
        return modelVersion;
    }

    public String getNormalizationVersion() {
        return normalizationVersion;
    }

    public LocalDateTime getAnalyzedAt() {
        return analyzedAt;
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

    /**
     * 신규 URL 분석 결과 생성
     */
    public UrlAnalysis(
            Long urlId,
            String resultToken,
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

        this.urlId = urlId;
        this.resultToken = resultToken;
        this.riskLevel = riskLevel;
        this.finalScore = finalScore;
        this.ruleScore = ruleScore;
        this.rfProbability = rfProbability;
        this.ruleFindings = ruleFindings;
        this.featuresJson = featuresJson;
        this.ruleVersion = ruleVersion;
        this.modelVersion = modelVersion;
        this.normalizationVersion = normalizationVersion;
        this.analyzedAt = analyzedAt;
        this.expiresAt = expiresAt;
    }

    /**
     * 기존 URL 분석 결과 갱신
     */
    public void updateAnalysis(
            String resultToken,
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

        this.resultToken = resultToken;
        this.riskLevel = riskLevel;
        this.finalScore = finalScore;
        this.ruleScore = ruleScore;
        this.rfProbability = rfProbability;
        this.ruleFindings = ruleFindings;
        this.featuresJson = featuresJson;
        this.ruleVersion = ruleVersion;
        this.modelVersion = modelVersion;
        this.normalizationVersion = normalizationVersion;
        this.analyzedAt = analyzedAt;
        this.expiresAt = expiresAt;
    }

}
