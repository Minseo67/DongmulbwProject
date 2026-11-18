
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

@Service
public class UrlAnalysisService {

    private final RuleBasedAnalysisService ruleBasedAnalysisService;
    private final DomainReputationService domainReputationService;
    private final PhishingUrlService phishingUrlService;
    private final ImportedListLookupService importedListLookupService;

    public UrlAnalysisService(
            RuleBasedAnalysisService ruleBasedAnalysisService,
            DomainReputationService domainReputationService,
            PhishingUrlService phishingUrlService,
            ImportedListLookupService importedListLookupService) {

        this.ruleBasedAnalysisService = ruleBasedAnalysisService;
        this.domainReputationService = domainReputationService;
        this.phishingUrlService = phishingUrlService;
        this.importedListLookupService = importedListLookupService;
    }

    public AnalysisResult analyze(
            String rawUrl,
            String normalizedUrl,
            String domain) {

        // 1. 기존 규칙 기반 분석
        RuleAnalysisResult ruleResult =
                ruleBasedAnalysisService.extract(rawUrl, domain);

        // 2. 기존 피싱 URL 검사
        boolean phishingUrlMatched =
                phishingUrlService.isPhishingUrl(rawUrl)
                || phishingUrlService.isPhishingUrl(normalizedUrl);

        // 3. 기존 도메인 평판 조회
        DomainReputationService.ReputationStatus reputationStatus =
                domainReputationService.checkDomain(domain);

        // 4. 신규 URL 블랙리스트 조회
        boolean importedBlacklisted =
                importedListLookupService.isBlacklisted(rawUrl)
                || importedListLookupService.isBlacklisted(normalizedUrl);

        // 5. 신규 도메인 화이트리스트 조회
        boolean importedWhitelisted =
                importedListLookupService.isWhitelisted(domain);

        // 6. 신규 목록과 기존 평판 결합
        if (importedBlacklisted) {
            reputationStatus =
                    DomainReputationService.ReputationStatus.BLACKLISTED;
        } else if (reputationStatus
                != DomainReputationService.ReputationStatus.BLACKLISTED
                && importedWhitelisted) {

            reputationStatus =
                    DomainReputationService.ReputationStatus.WHITELISTED;
        }

        // 7. 블랙리스트 우선 적용
        if (reputationStatus
                == DomainReputationService.ReputationStatus.BLACKLISTED) {

            ruleResult = withAdjustedRuleScore(ruleResult, 100.0);

        // 8. 화이트리스트는 피싱 URL 미일치 시 10점 감점
        } else if (reputationStatus
                == DomainReputationService.ReputationStatus.WHITELISTED
                && !phishingUrlMatched) {

            double adjustedScore =
                    Math.max(0.0, ruleResult.suspiciousScore() - 10.0);

            ruleResult = withAdjustedRuleScore(ruleResult, adjustedScore);
        }

        return new AnalysisResult(
                ruleResult,
                reputationStatus,
                phishingUrlMatched
        );
    }

    private RuleAnalysisResult withAdjustedRuleScore(
            RuleAnalysisResult original,
            double score) {

        String riskLevel = score >= 60 ? "DANGER"
                : score >= 30 ? "WARNING" : "SAFE";

        return new RuleAnalysisResult(
                original.domainLength(),
                original.hyphenCount(),
                original.dotCount(),
                original.digitCount(),
                original.hasIpAddress(),
                original.hasPunycode(),
                original.hasSuspiciousKeyword(),
                original.hasSuspiciousTld(),
                original.hasBrandImpersonation(),
                original.hasSubdomainBrandImpersonation(),
                original.hasShortUrlService(),
                original.queryParamCount(),
                score,
                riskLevel,
                original.findings()
        );
    }

    public record AnalysisResult(
            RuleAnalysisResult ruleResult,
            DomainReputationService.ReputationStatus reputationStatus,
            boolean phishingUrlMatched
    ) {}
}