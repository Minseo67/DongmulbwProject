
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;

@Service
public class UrlAnalysisService {

        private final RuleBasedAnalysisService ruleBasedAnalysisService;
        private final DomainReputationService domainReputationService;
        private final PhishingUrlService phishingUrlService;

        public UrlAnalysisService(
                        RuleBasedAnalysisService ruleBasedAnalysisService,
                        DomainReputationService domainReputationService,
                        PhishingUrlService phishingUrlService) {

                this.ruleBasedAnalysisService = ruleBasedAnalysisService;
                this.domainReputationService = domainReputationService;
                this.phishingUrlService = phishingUrlService;
        }

        public AnalysisResult analyze(
                        String rawUrl,
                        String normalizedUrl,
                        String domain) {

                // 1. 기존 규칙 기반 분석
                RuleAnalysisResult ruleResult = ruleBasedAnalysisService.extract(rawUrl, domain);

                // 2. 피싱 URL 데이터셋 일치 여부 확인
                boolean phishingUrlMatched = phishingUrlService.isPhishingUrl(rawUrl)
                                || phishingUrlService.isPhishingUrl(normalizedUrl);

                // 3. 도메인 평판 확인
                DomainReputationService.ReputationStatus reputationStatus = domainReputationService.checkDomain(domain);

                // 4. 블랙리스트는 기존대로 규칙 점수 100점 적용
                if (reputationStatus == DomainReputationService.ReputationStatus.BLACKLISTED) {

                        ruleResult = withAdjustedRuleScore(ruleResult, 100.0);

                        // 5. 화이트리스트는 피싱 URL과 일치하지 않을 때만 할인
                } else if (reputationStatus == DomainReputationService.ReputationStatus.WHITELISTED
                                && !phishingUrlMatched) {

                        double adjustedScore = Math.max(0.0, ruleResult.suspiciousScore() - 10.0);

                        ruleResult = withAdjustedRuleScore(ruleResult, adjustedScore);
                }

                // 6. 기존 반환 구조 유지
                return new AnalysisResult(
                                ruleResult,
                                reputationStatus,
                                phishingUrlMatched);
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
                                original.findings());
        }

        public record AnalysisResult(
                        RuleAnalysisResult ruleResult,
                        DomainReputationService.ReputationStatus reputationStatus,
                        boolean phishingUrlMatched) {
        }
}
