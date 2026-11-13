
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UrlAnalysisServiceTest {

    private RuleBasedAnalysisService ruleBasedAnalysisService;
    private DomainReputationService domainReputationService;
    private PhishingUrlService phishingUrlService;
    private ImportedListLookupService importedListLookupService;
    private UrlAnalysisService urlAnalysisService;

    @BeforeEach
    void setUp() {
        // 실제 서비스 및 DB 조회를 실행하지 않도록 Mock 객체 생성
        ruleBasedAnalysisService = mock(RuleBasedAnalysisService.class);
        domainReputationService = mock(DomainReputationService.class);
        phishingUrlService = mock(PhishingUrlService.class);
        importedListLookupService = mock(ImportedListLookupService.class);

        // 신규 ImportedListLookupService까지 포함한 생성자
        urlAnalysisService = new UrlAnalysisService(
                ruleBasedAnalysisService,
                domainReputationService,
                phishingUrlService,
                importedListLookupService
        );
    }

    /**
     * 테스트용 규칙 분석 결과 생성
     */
    private RuleAnalysisResult createRuleResult(double score) {
        String level = score >= 60 ? "DANGER"
                : score >= 30 ? "WARNING" : "SAFE";

        return new RuleAnalysisResult(
                10, 0, 1, 0,
                false, false, false, false,
                false, false, false, 0,
                score, level, List.of()
        );
    }

    /**
     * 특정 URL에 대한 규칙 점수와 도메인 평판 설정
     */
    private void prepareAnalysis(
            String url,
            String domain,
            double score,
            DomainReputationService.ReputationStatus status) {

        when(ruleBasedAnalysisService.extract(url, domain))
                .thenReturn(createRuleResult(score));

        when(domainReputationService.checkDomain(domain))
                .thenReturn(status);
    }

    /**
     * 1. 기존 블랙리스트는 규칙 점수를 100점으로 변경
     */
    @Test
    void blacklistForcesRuleScoreTo100() {
        String url = "http://malicious.example/login";
        String domain = "malicious.example";

        prepareAnalysis(
                url, domain, 20,
                DomainReputationService.ReputationStatus.BLACKLISTED
        );

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(100.0, result.ruleResult().suspiciousScore());
        assertEquals("DANGER", result.ruleResult().riskLevel());
        assertEquals(
                DomainReputationService.ReputationStatus.BLACKLISTED,
                result.reputationStatus()
        );
    }

    /**
     * 2. 화이트리스트는 규칙 점수에서 10점 차감
     */
    @Test
    void whitelistDeducts10FromRuleScore() {
        String url = "https://trusted.example/home";
        String domain = "trusted.example";

        prepareAnalysis(
                url, domain, 65,
                DomainReputationService.ReputationStatus.WHITELISTED
        );

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(55.0, result.ruleResult().suspiciousScore());
        assertEquals("WARNING", result.ruleResult().riskLevel());
    }

    /**
     * 3. 화이트리스트 감점 후 점수는 음수가 될 수 없음
     */
    @Test
    void whitelistScoreCannotBecomeNegative() {
        String url = "https://trusted.example/";
        String domain = "trusted.example";

        prepareAnalysis(
                url, domain, 5,
                DomainReputationService.ReputationStatus.WHITELISTED
        );

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(0.0, result.ruleResult().suspiciousScore());
        assertEquals("SAFE", result.ruleResult().riskLevel());
    }

    /**
     * 4. 만료된 화이트리스트는 감점하지 않음
     */
    @Test
    void expiredWhitelistDoesNotDeductScore() {
        String url = "https://expired.example/";
        String domain = "expired.example";

        prepareAnalysis(
                url, domain, 65,
                DomainReputationService.ReputationStatus.EXPIRED
        );

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(65.0, result.ruleResult().suspiciousScore());
        assertEquals("DANGER", result.ruleResult().riskLevel());
    }

    /**
     * 5. 평판 정보가 없는 도메인은 원래 점수 유지
     */
    @Test
    void unknownDomainKeepsRuleScore() {
        String url = "https://unknown.example/path";
        String domain = "unknown.example";

        prepareAnalysis(
                url, domain, 35,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(35.0, result.ruleResult().suspiciousScore());
        assertEquals("WARNING", result.ruleResult().riskLevel());
    }

    /**
     * 6. 피싱 URL 목록에 존재하면 true 반환
     */
    @Test
    void phishingUrlMatchReturnsTrue() {
        String url = "https://phishing-test.invalid/login";
        String domain = "phishing-test.invalid";

        prepareAnalysis(
                url, domain, 40,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        when(phishingUrlService.isPhishingUrl(url))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertTrue(result.phishingUrlMatched());
    }

    /**
     * 7. 피싱 URL 목록에 없으면 false 반환
     */
    @Test
    void phishingUrlNotMatchedReturnsFalse() {
        String url = "https://example.com/";
        String domain = "example.com";

        prepareAnalysis(
                url, domain, 10,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertFalse(result.phishingUrlMatched());
    }

    /**
     * 8. 원본 URL이 불일치해도 정규화 URL이 일치하면 탐지
     */
    @Test
    void normalizedUrlMatchReturnsTrueWhenRawUrlDoesNotMatch() {
        String rawUrl = "HTTPS://example.com/login";
        String normalizedUrl = "https://example.com/login";
        String domain = "example.com";

        prepareAnalysis(
                rawUrl, domain, 20,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        when(phishingUrlService.isPhishingUrl(rawUrl))
                .thenReturn(false);

        when(phishingUrlService.isPhishingUrl(normalizedUrl))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(rawUrl, normalizedUrl, domain);

        assertTrue(result.phishingUrlMatched());

        verify(phishingUrlService).isPhishingUrl(rawUrl);
        verify(phishingUrlService).isPhishingUrl(normalizedUrl);
    }

    /**
     * 9. 반복 분석해도 화이트리스트 감점은 누적되지 않음
     */
    @Test
    void whitelistDeductionIsNotAccumulated() {
        String url = "https://trusted.example/home";
        String domain = "trusted.example";

        prepareAnalysis(
                url, domain, 65.0,
                DomainReputationService.ReputationStatus.WHITELISTED
        );

        UrlAnalysisService.AnalysisResult first =
                urlAnalysisService.analyze(url, url, domain);

        UrlAnalysisService.AnalysisResult second =
                urlAnalysisService.analyze(url, url, domain);

        UrlAnalysisService.AnalysisResult third =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(55.0, first.ruleResult().suspiciousScore());
        assertEquals(55.0, second.ruleResult().suspiciousScore());
        assertEquals(55.0, third.ruleResult().suspiciousScore());

        assertEquals("WARNING", first.ruleResult().riskLevel());
        assertEquals("WARNING", second.ruleResult().riskLevel());
        assertEquals("WARNING", third.ruleResult().riskLevel());

        verify(ruleBasedAnalysisService, times(3))
                .extract(url, domain);

        verify(domainReputationService, times(3))
                .checkDomain(domain);
    }

    /**
     * 10. 피싱 URL이면 화이트리스트 감점을 적용하지 않음
     */
    @Test
    void phishingUrlMatchPreventsWhitelistDeduction() {
        String url = "https://trusted.example/phishing";
        String domain = "trusted.example";

        prepareAnalysis(
                url, domain, 65.0,
                DomainReputationService.ReputationStatus.WHITELISTED
        );

        when(phishingUrlService.isPhishingUrl(url))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(65.0, result.ruleResult().suspiciousScore());
        assertEquals("DANGER", result.ruleResult().riskLevel());

        assertTrue(result.phishingUrlMatched());
        assertEquals(
                DomainReputationService.ReputationStatus.WHITELISTED,
                result.reputationStatus()
        );
    }

    /**
     * 11. 정규화 URL이 피싱 목록에 있으면 화이트리스트 감점 제외
     */
    @Test
    void normalizedPhishingUrlPreventsWhitelistDeduction() {
        String rawUrl = "HTTPS://trusted.example/phishing";
        String normalizedUrl = "https://trusted.example/phishing";
        String domain = "trusted.example";

        prepareAnalysis(
                rawUrl, domain, 40.0,
                DomainReputationService.ReputationStatus.WHITELISTED
        );

        when(phishingUrlService.isPhishingUrl(rawUrl))
                .thenReturn(false);

        when(phishingUrlService.isPhishingUrl(normalizedUrl))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(
                        rawUrl,
                        normalizedUrl,
                        domain
                );

        assertEquals(40.0, result.ruleResult().suspiciousScore());
        assertEquals("WARNING", result.ruleResult().riskLevel());
        assertTrue(result.phishingUrlMatched());

        verify(phishingUrlService).isPhishingUrl(rawUrl);
        verify(phishingUrlService).isPhishingUrl(normalizedUrl);
    }

    /**
     * 12. 신규 DB 블랙리스트에 등록된 URL은 100점 처리
     */
    @Test
    void importedBlacklistForcesRuleScoreTo100() {
        String url = "https://blocked.example/login";
        String domain = "blocked.example";

        prepareAnalysis(
                url, domain, 20,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        when(importedListLookupService.isBlacklisted(url))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(100.0, result.ruleResult().suspiciousScore());
        assertEquals("DANGER", result.ruleResult().riskLevel());
        assertEquals(
                DomainReputationService.ReputationStatus.BLACKLISTED,
                result.reputationStatus()
        );
    }

    /**
     * 13. 신규 DB 화이트리스트에 등록된 도메인은 10점 감점
     */
    @Test
    void importedWhitelistDeducts10FromRuleScore() {
        String url = "https://trusted.example/home";
        String domain = "trusted.example";

        prepareAnalysis(
                url, domain, 65,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        when(importedListLookupService.isWhitelisted(domain))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(55.0, result.ruleResult().suspiciousScore());
        assertEquals("WARNING", result.ruleResult().riskLevel());
        assertEquals(
                DomainReputationService.ReputationStatus.WHITELISTED,
                result.reputationStatus()
        );
    }

    /**
     * 14. 신규 블랙리스트와 화이트리스트가 충돌하면 블랙리스트 우선
     */
    @Test
    void importedBlacklistOverridesWhitelist() {
        String url = "https://trusted.example/phishing";
        String domain = "trusted.example";

        prepareAnalysis(
                url, domain, 20,
                DomainReputationService.ReputationStatus.UNKNOWN
        );

        when(importedListLookupService.isBlacklisted(url))
                .thenReturn(true);

        when(importedListLookupService.isWhitelisted(domain))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result =
                urlAnalysisService.analyze(url, url, domain);

        assertEquals(100.0, result.ruleResult().suspiciousScore());
        assertEquals("DANGER", result.ruleResult().riskLevel());
        assertEquals(
                DomainReputationService.ReputationStatus.BLACKLISTED,
                result.reputationStatus()
        );
    }
}
