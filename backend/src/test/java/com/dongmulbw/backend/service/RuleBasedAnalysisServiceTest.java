
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RuleBasedAnalysisServiceTest {

    private final RuleBasedAnalysisService service = new RuleBasedAnalysisService();

    @Test
    void normalUrl() {
        RuleAnalysisResult result = service.extract("https://example.com", "example.com");

        assertEquals(0.0, result.suspiciousScore());
        assertFalse(result.hasSuspiciousKeyword());
        assertFalse(result.hasBrandImpersonation());
        assertFalse(result.hasShortUrlService());
    }

    @Test
    void longDomain() {
        String domain = "abcdefghijklmnopqrstuvwxyz1234.com";

        RuleAnalysisResult result = service.extract("https://" + domain, domain);

        assertTrue(result.domainLength() >= 30);
        assertEquals(25.0, result.suspiciousScore());
    }

    @Test
    void ipAddress() {
        RuleAnalysisResult result = service.extract("http://192.168.0.1", "192.168.0.1");

        assertTrue(result.hasIpAddress());
        assertEquals(55.0, result.suspiciousScore());
    }

    @Test
    void punycode() {
        RuleAnalysisResult result = service.extract("https://xn--test.com", "xn--test.com");

        assertTrue(result.hasPunycode());
        assertEquals(2, result.hyphenCount());
        assertFalse(result.hasShortUrlService());
        assertEquals(40.0, result.suspiciousScore());
    }

    @Test
    void suspiciousKeyword() {
        RuleAnalysisResult result = service.extract("https://example.com/login", "example.com");

        assertTrue(result.hasSuspiciousKeyword());
        assertEquals(20.0, result.suspiciousScore());
    }

    @Test
    void suspiciousTld() {
        RuleAnalysisResult result = service.extract("https://example.xyz", "example.xyz");

        assertTrue(result.hasSuspiciousTld());
        assertEquals(20.0, result.suspiciousScore());
    }

    @Test
    void shortUrl() {
        RuleAnalysisResult result = service.extract("https://bit.ly/abc", "bit.ly");

        assertTrue(result.hasShortUrlService());
        assertEquals(20.0, result.suspiciousScore());
    }

    @Test
    void brandImpersonation() {
        RuleAnalysisResult result = service.extract(
                "https://google-login.xyz",
                "google-login.xyz");

        assertTrue(result.hasBrandImpersonation());
        assertTrue(result.hasSuspiciousKeyword());
        assertEquals(100.0, result.suspiciousScore());
    }

    @Test
    void officialDomain() {
        RuleAnalysisResult result = service.extract("https://google.com", "google.com");

        assertFalse(result.hasBrandImpersonation());
        assertFalse(result.hasSubdomainBrandImpersonation());
        assertEquals(0.0, result.suspiciousScore());
    }

    @Test
    void subdomainBrandImpersonation() {
        RuleAnalysisResult result = service.extract(
                "https://google.login.example.com",
                "google.login.example.com");

        assertTrue(result.hasSubdomainBrandImpersonation());
        assertEquals(100.0, result.suspiciousScore());
    }

    @Test
    void scoreMaximum() {
        RuleAnalysisResult result = service.extract(
                "http://google-login-1234.verify.xyz",
                "google-login-1234.verify.xyz");

        assertEquals(100.0, result.suspiciousScore());
    }

    // 추가 테스트 1: t.co 문자열이 포함된 일반 도메인
    @Test
    void shortUrlFalsePositivePrevention() {
        RuleAnalysisResult result = service.extract("https://test.com", "test.com");

        assertFalse(result.hasShortUrlService());
        assertEquals(0.0, result.suspiciousScore());
    }

    // 추가 테스트 2: 단축 URL처럼 보이는 가짜 도메인
    @Test
    void fakeShortUrlDomain() {
        RuleAnalysisResult result = service.extract(
                "https://fake-bit.ly.com",
                "fake-bit.ly.com");

        assertFalse(result.hasShortUrlService());
        assertEquals(0.0, result.suspiciousScore());
    }

    // 추가 테스트 3: 실제 t.co 단축 URL
    @Test
    void actualTcoShortUrl() {
        RuleAnalysisResult result = service.extract("https://t.co/abc", "t.co");

        assertTrue(result.hasShortUrlService());
        assertEquals(20.0, result.suspiciousScore());
    }
}
