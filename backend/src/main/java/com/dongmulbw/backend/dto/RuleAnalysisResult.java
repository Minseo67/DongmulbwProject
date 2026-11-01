
package com.dongmulbw.backend.dto;

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
        double suspiciousScore) {
}
