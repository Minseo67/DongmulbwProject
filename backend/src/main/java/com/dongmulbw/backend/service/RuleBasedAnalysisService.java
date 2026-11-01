
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;

@Component
public class RuleBasedAnalysisService {

    private static final Set<String> SHORT_URL_DOMAINS = Set.of(
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "cutt.ly",
            "is.gd",
            "ow.ly",
            "rebrand.ly",
            "shorturl.at",
            "url.kr",
            "vo.la",
            "han.gl",
            "me2.kr");

    public RuleAnalysisResult extract(String url, String domain) {

        if (url == null) {
            url = "";
        }

        if (domain == null) {
            domain = "";
        }

        boolean hasBrandImpersonation = containsBrandImpersonation(domain);
        boolean hasSubdomainBrandImpersonation = containsSubdomainBrandImpersonation(domain);

        int domainLength = domain.length();
        int hyphenCount = countChar(domain, '-');
        int dotCount = countChar(domain, '.');
        int digitCount = countDigits(domain);

        boolean hasIpAddress = url.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*");
        boolean hasPunycode = domain.contains("xn--");
        boolean hasSuspiciousKeyword = containsSuspiciousKeyword(url);
        boolean hasSuspiciousTld = hasSuspiciousTld(domain);
        boolean hasShortUrlService = hasShortUrlService(domain);

        int queryParamCount = countQueryParams(url);
        boolean usesHttp = url.regionMatches(true, 0, "http://", 0, 7);

        double score = calculateScore(
                domainLength,
                hyphenCount,
                dotCount,
                digitCount,
                hasIpAddress,
                hasPunycode,
                hasSuspiciousKeyword,
                hasSuspiciousTld,
                hasBrandImpersonation,
                hasSubdomainBrandImpersonation,
                hasShortUrlService,
                queryParamCount,
                usesHttp);

        return new RuleAnalysisResult(
                domainLength,
                hyphenCount,
                dotCount,
                digitCount,
                hasIpAddress,
                hasPunycode,
                hasSuspiciousKeyword,
                hasSuspiciousTld,
                hasBrandImpersonation,
                hasSubdomainBrandImpersonation,
                hasShortUrlService,
                queryParamCount,
                score);
    }

    private int countChar(String text, char target) {
        return (int) text.chars()
                .filter(ch -> ch == target)
                .count();
    }

    private int countDigits(String text) {
        return (int) text.chars()
                .filter(Character::isDigit)
                .count();
    }

    private int countQueryParams(String url) {
        try {
            String query = new URI(url).getRawQuery();

            if (query == null || query.isEmpty()) {
                return 0;
            }

            int count = 0;

            for (String part : query.split("&", -1)) {
                if (!part.isEmpty()) {
                    count++;
                }
            }

            return count;
        } catch (URISyntaxException e) {
            return 0;
        }
    }

    private boolean containsSuspiciousKeyword(String url) {
        String lower = url.toLowerCase(Locale.ROOT);

        return lower.contains("login")
                || lower.contains("verify")
                || lower.contains("secure")
                || lower.contains("account")
                || lower.contains("update")
                || lower.contains("bank")
                || lower.contains("paypal")
                || lower.contains("confirm");
    }

    private boolean isOfficialDomain(String domain) {
        String lower = domain.toLowerCase(Locale.ROOT);

        return lower.equals("google.com")
                || lower.endsWith(".google.com")
                || lower.equals("naver.com")
                || lower.endsWith(".naver.com")
                || lower.equals("kakao.com")
                || lower.endsWith(".kakao.com")
                || lower.equals("paypal.com")
                || lower.endsWith(".paypal.com")
                || lower.equals("microsoft.com")
                || lower.endsWith(".microsoft.com")
                || lower.equals("apple.com")
                || lower.endsWith(".apple.com")
                || lower.equals("amazon.com")
                || lower.endsWith(".amazon.com");
    }

    private boolean containsBrandImpersonation(String domain) {

        if (domain == null || isOfficialDomain(domain)) {
            return false;
        }

        String lower = domain.toLowerCase(Locale.ROOT);

        return lower.contains("google")
                || lower.contains("g00gle")
                || lower.contains("goog1e")
                || lower.contains("gooogle")
                || lower.contains("naver")
                || lower.contains("n@ver")
                || lower.contains("kakao")
                || lower.contains("paypal")
                || lower.contains("paypa1")
                || lower.contains("paypai")
                || lower.contains("microsoft")
                || lower.contains("micros0ft")
                || lower.contains("rnicrosoft")
                || lower.contains("apple")
                || lower.contains("app1e")
                || lower.contains("amazon")
                || lower.contains("amaz0n");
    }

    private boolean containsSubdomainBrandImpersonation(String domain) {

        if (domain == null || domain.isBlank()
                || isOfficialDomain(domain)) {
            return false;
        }

        String lower = domain.toLowerCase(Locale.ROOT);
        String[] parts = lower.split("\\.");

        if (parts.length < 3) {
            return false;
        }

        for (int i = 0; i < parts.length - 2; i++) {
            String sub = parts[i];

            if (sub.equals("google")
                    || sub.equals("naver")
                    || sub.equals("kakao")
                    || sub.equals("paypal")
                    || sub.equals("microsoft")
                    || sub.equals("apple")
                    || sub.equals("amazon")) {
                return true;
            }
        }

        return lower.contains("google.login")
                || lower.contains("paypal.verify")
                || lower.contains("naver.login")
                || lower.contains("kakao.login")
                || lower.contains("microsoft.login");
    }

    private boolean hasSuspiciousTld(String domain) {

        if (domain == null) {
            return false;
        }

        String lower = domain.toLowerCase(Locale.ROOT).trim();

        return lower.equals("xyz")
                || lower.endsWith(".xyz")
                || lower.endsWith(".top")
                || lower.endsWith(".click")
                || lower.endsWith(".gq")
                || lower.endsWith(".ru");
    }

    private boolean hasShortUrlService(String domain) {

        if (domain == null || domain.isBlank()) {
            return false;
        }

        String lower = domain.toLowerCase(Locale.ROOT);

        for (String shortDomain : SHORT_URL_DOMAINS) {
            if (lower.equals(shortDomain)
                    || lower.endsWith("." + shortDomain)) {
                return true;
            }
        }

        return false;
    }

    private double calculateScore(
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
            boolean usesHttp) {

        double score = 0;

        if (domainLength >= 30) {
            score += 15;
        }

        if (hyphenCount >= 2) {
            score += 15;
        }

        if (dotCount >= 3) {
            score += 15;
        }

        if (digitCount >= 3) {
            score += 10;
        }

        if (hasIpAddress) {
            score += 30;
        }

        if (hasPunycode) {
            score += 25;
        }

        if (hasSuspiciousKeyword) {
            score += 20;
        }

        if (hasSuspiciousTld) {
            score += 20;
        }

        if (hasShortUrlService) {
            score += 20;
        }

        if (hasBrandImpersonation) {
            score += 50;
        }

        if (hasBrandImpersonation && hasSuspiciousKeyword) {
            score += 20;
        }

        if (hasSubdomainBrandImpersonation) {
            score += 35;
        }

        if (hasSubdomainBrandImpersonation && hasSuspiciousKeyword) {
            score += 20;
        }

        if (hasShortUrlService && hasBrandImpersonation) {
            score += 15;
        }

        // 쿼리 파라미터 3개 이상
        if (queryParamCount >= 3) {
            score += 10;
        }

        // 신규 규칙: HTTP 사용 + 도메인 점 2개
        if (dotCount == 2 && usesHttp) {
            score += 10;
        }

        return Math.min(score, 100);
    }

}
