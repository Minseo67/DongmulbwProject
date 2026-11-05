package com.dongmulbw.backend.dto;

import java.util.List;

public record RuleAnalysisResult(
        int domainLength,
        int hyphenCount,
        int dotCount,
        int digitCount,
        boolean hasIpAddress,
        boolean hasPunycode,
        boolean hasSuspiciousKeyword,
        boolean hasSuspiciousTld,
        boolean hasBrandImpersonation,
        boolean hasSubdomainBrandImpersonation,
        boolean hasShortUrlService,
        int queryParamCount,
        double suspiciousScore,
        String riskLevel,
        List<RuleFinding> findings) {
    public record RuleFinding(
            String reason,
            int points) {
    }
}