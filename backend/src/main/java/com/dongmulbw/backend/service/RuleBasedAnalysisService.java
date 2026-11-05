
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import com.dongmulbw.backend.dto.RuleAnalysisResult.RuleFinding;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
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

        List<RuleFinding> findings = collectFindings(
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

        double score = Math.min(100, findings.stream()
                .mapToInt(RuleFinding::points)
                .sum());

        String riskLevel = classifyRiskLevel(score);

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
                score,
                riskLevel,
                findings);
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

    private List<RuleFinding> collectFindings(
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

        List<RuleFinding> findings = new ArrayList<>();

        if (domainLength >= 30) {
            findings.add(new RuleFinding("도메인 길이 30자 이상", 15));
        }

        if (hyphenCount >= 2) {
            findings.add(new RuleFinding("도메인 하이픈 2개 이상", 15));
        }

        if (dotCount >= 3) {
            findings.add(new RuleFinding("도메인 점 3개 이상", 15));
        }

        if (digitCount >= 3) {
            findings.add(new RuleFinding("도메인 숫자 3개 이상", 10));
        }

        if (hasIpAddress) {
            findings.add(new RuleFinding("IP 주소 사용", 30));
        }

        if (hasPunycode) {
            findings.add(new RuleFinding("Punycode 사용", 25));
        }

        if (hasSuspiciousKeyword) {
            findings.add(new RuleFinding("의심 키워드 포함", 20));
        }

        if (hasSuspiciousTld) {
            findings.add(new RuleFinding("의심 TLD 사용", 20));
        }

        if (hasShortUrlService) {
            findings.add(new RuleFinding("단축 URL 서비스", 20));
        }

        if (hasBrandImpersonation) {
            findings.add(new RuleFinding("브랜드 사칭 패턴", 50));
        }

        if (hasBrandImpersonation && hasSuspiciousKeyword) {
            findings.add(new RuleFinding("브랜드 사칭 + 의심 키워드", 20));
        }

        if (hasSubdomainBrandImpersonation) {
            findings.add(new RuleFinding("서브도메인 브랜드 사칭", 35));
        }

        if (hasSubdomainBrandImpersonation && hasSuspiciousKeyword) {
            findings.add(new RuleFinding("서브도메인 사칭 + 의심 키워드", 20));
        }

        if (hasShortUrlService && hasBrandImpersonation) {
            findings.add(new RuleFinding("단축 URL + 브랜드 사칭", 15));
        }

        if (queryParamCount >= 3) {
            findings.add(new RuleFinding("쿼리 파라미터 3개 이상", 10));
        }

        if (dotCount == 2 && usesHttp) {
            findings.add(new RuleFinding("HTTP + 도메인 점 2개", 10));
        }

        return findings;
    }

    private String classifyRiskLevel(double score) {
        if (score >= 60) {
            return "DANGER";
        }

        if (score >= 30) {
            return "WARNING";
        }

        return "SAFE";
    }
}
