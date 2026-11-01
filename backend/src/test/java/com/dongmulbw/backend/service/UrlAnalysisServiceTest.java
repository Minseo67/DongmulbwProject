
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UrlAnalysisServiceTest {

    private RuleBasedAnalysisService ruleBasedAnalysisService;
    private DomainReputationService domainReputationService;
    private PhishingUrlService phishingUrlService;
    private UrlAnalysisService urlAnalysisService;

    @BeforeEach
    void setUp() {
        ruleBasedAnalysisService = mock(RuleBasedAnalysisService.class);
        domainReputationService = mock(DomainReputationService.class);
        phishingUrlService = mock(PhishingUrlService.class);

        urlAnalysisService = new UrlAnalysisService(
                ruleBasedAnalysisService,
                domainReputationService,
                phishingUrlService);
    }

    @Test
    void blacklistedDomainReturnsBothResults() {
        String url = "http://malicious.example/login";
        String domain = "malicious.example";

        RuleAnalysisResult ruleResult = mock(RuleAnalysisResult.class);

        when(ruleBasedAnalysisService.extract(url, domain))
                .thenReturn(ruleResult);

        when(domainReputationService.checkDomain(domain))
                .thenReturn(
                        DomainReputationService.ReputationStatus.BLACKLISTED);

        UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

        assertSame(ruleResult, result.ruleResult());

        assertEquals(
                DomainReputationService.ReputationStatus.BLACKLISTED,
                result.reputationStatus());

        assertFalse(result.phishingUrlMatched());

        verify(ruleBasedAnalysisService).extract(url, domain);
        verify(domainReputationService).checkDomain(domain);
        verify(phishingUrlService, times(2)).isPhishingUrl(url);
    }

    @Test
    void whitelistedDomainReturnsBothResults() {
        String url = "https://trusted.example/home";
        String domain = "trusted.example";

        RuleAnalysisResult ruleResult = mock(RuleAnalysisResult.class);

        when(ruleBasedAnalysisService.extract(url, domain))
                .thenReturn(ruleResult);

        when(domainReputationService.checkDomain(domain))
                .thenReturn(
                        DomainReputationService.ReputationStatus.WHITELISTED);

        UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

        assertSame(ruleResult, result.ruleResult());

        assertEquals(
                DomainReputationService.ReputationStatus.WHITELISTED,
                result.reputationStatus());

        assertFalse(result.phishingUrlMatched());
    }

    @Test
    void unknownDomainKeepsRuleResult() {
        String url = "https://unknown.example/path";
        String domain = "unknown.example";

        RuleAnalysisResult ruleResult = mock(RuleAnalysisResult.class);

        when(ruleBasedAnalysisService.extract(url, domain))
                .thenReturn(ruleResult);

        when(domainReputationService.checkDomain(domain))
                .thenReturn(
                        DomainReputationService.ReputationStatus.UNKNOWN);

        UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

        assertSame(ruleResult, result.ruleResult());

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                result.reputationStatus());

        assertFalse(result.phishingUrlMatched());
    }

    @Test
    void phishingUrlMatchReturnsTrue() {
        String url = "https://phishing-test.invalid/login";
        String domain = "phishing-test.invalid";

        RuleAnalysisResult ruleResult = mock(RuleAnalysisResult.class);

        when(ruleBasedAnalysisService.extract(url, domain))
                .thenReturn(ruleResult);

        when(domainReputationService.checkDomain(domain))
                .thenReturn(
                        DomainReputationService.ReputationStatus.UNKNOWN);

        when(phishingUrlService.isPhishingUrl(url))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

        assertSame(ruleResult, result.ruleResult());

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                result.reputationStatus());

        assertTrue(result.phishingUrlMatched());

        verify(phishingUrlService).isPhishingUrl(url);

    }

    @Test
    void phishingUrlNotMatchedReturnsFalse() {
        String url = "https://example.com/";
        String domain = "example.com";

        RuleAnalysisResult ruleResult = mock(RuleAnalysisResult.class);

        when(ruleBasedAnalysisService.extract(url, domain))
                .thenReturn(ruleResult);

        when(domainReputationService.checkDomain(domain))
                .thenReturn(
                        DomainReputationService.ReputationStatus.UNKNOWN);

        when(phishingUrlService.isPhishingUrl(url))
                .thenReturn(false);

        UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

        assertSame(ruleResult, result.ruleResult());
        assertFalse(result.phishingUrlMatched());

        verify(phishingUrlService, times(2)).isPhishingUrl(url);
    }

    @Test
    void normalizedUrlMatchReturnsTrueWhenRawUrlDoesNotMatch() {
        String rawUrl = "HTTPS://example.com/login";
        String normalizedUrl = "https://example.com/login";
        String domain = "example.com";

        when(phishingUrlService.isPhishingUrl(rawUrl))
                .thenReturn(false);

        when(phishingUrlService.isPhishingUrl(normalizedUrl))
                .thenReturn(true);

        UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(rawUrl, normalizedUrl, domain);

        assertTrue(result.phishingUrlMatched());

        verify(phishingUrlService).isPhishingUrl(rawUrl);
        verify(phishingUrlService).isPhishingUrl(normalizedUrl);
    }

}
