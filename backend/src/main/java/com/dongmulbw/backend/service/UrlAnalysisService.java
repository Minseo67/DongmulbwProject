
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

                // 1. 원본 URL로 규칙 기반 분석
                RuleAnalysisResult ruleResult = ruleBasedAnalysisService.extract(rawUrl, domain);

                // 2. 기존 DB 도메인 평판 조회
                DomainReputationService.ReputationStatus reputationStatus = domainReputationService.checkDomain(domain);

                // 3. 원본 URL 또는 정규화된 URL이 피싱 목록에 있는지 확인
                boolean phishingUrlMatched = phishingUrlService.isPhishingUrl(rawUrl)
                                || phishingUrlService.isPhishingUrl(normalizedUrl);

                // 4. 세 가지 분석 결과 반환
                return new AnalysisResult(
                                ruleResult,
                                reputationStatus,
                                phishingUrlMatched);
        }

        public record AnalysisResult(
                        RuleAnalysisResult ruleResult,
                        DomainReputationService.ReputationStatus reputationStatus,
                        boolean phishingUrlMatched) {
        }
}
