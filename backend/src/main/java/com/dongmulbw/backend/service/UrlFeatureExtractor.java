
package com.dongmulbw.backend.service;

import com.google.common.net.InternetDomainName;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;

@Service
public class UrlFeatureExtractor {

    // feature_names.json 순서와 동일
    private static final List<String> FEATURE_NAMES = List.of(
            "url_length",
            "hostname_length",
            "domain_length",
            "subdomain_count",
            "dot_count",
            "hyphen_count",
            "digit_count",
            "special_char_count",
            "digit_ratio",
            "has_ip_address",
            "has_https",
            "has_at_symbol",
            "path_length",
            "path_depth",
            "query_param_count",
            "has_punycode",
            "suspicious_keyword_count",
            "url_entropy",
            "has_url_shortener",
            "brand_similarity",
            "scheme_missing");

    private static final List<String> SUSPICIOUS_KEYWORDS = List.of(
            "login", "verify", "account", "secure",
            "update", "confirm", "password",
            "signin", "bank", "payment");

    private static final Set<String> URL_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co",
            "goo.gl", "ow.ly", "is.gd",
            "buff.ly", "cutt.ly", "rebrand.ly");

    private static final List<String> BRAND_DOMAINS = List.of(
            "google.com", "naver.com", "kakao.com",
            "youtube.com", "facebook.com",
            "instagram.com", "amazon.com",
            "microsoft.com", "apple.com", "paypal.com");

    // URL에서 특징 21개를 추출
    public Map<String, Float> extractFeatures(String rawUrl) {

        if (rawUrl == null || rawUrl.isBlank()) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        String url = rawUrl.strip();

        boolean hasExplicitScheme = url.matches(
                "(?s)^[A-Za-z][A-Za-z0-9+.-]*://.*");

        // 스킴이 없으면 파싱할 때만 http://를 임시 추가
        String parsingUrl = hasExplicitScheme
                ? url
                : "http://" + url;

        URI uri;
        try {
            uri = URI.create(parsingUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("INVALID_URL", e);
        }

        String hostname = Optional.ofNullable(uri.getHost())
                .orElse("")
                .toLowerCase(Locale.ROOT);

        String path = Optional.ofNullable(uri.getRawPath())
                .orElse("");

        String query = Optional.ofNullable(uri.getRawQuery())
                .orElse("");

        // 등록 가능 도메인과 서브도메인 분리
        String registeredDomain = hostname;
        int subdomainCount = 0;

        try {
            InternetDomainName domain = InternetDomainName.from(hostname);

            if (domain.isUnderPublicSuffix()) {
                registeredDomain = domain.topPrivateDomain().toString();

                String prefix = hostname.substring(
                        0,
                        hostname.length() - registeredDomain.length());

                if (prefix.endsWith(".")) {
                    prefix = prefix.substring(0, prefix.length() - 1);
                }

                if (!prefix.isEmpty()) {
                    subdomainCount = prefix.split("\\.").length;
                }
            }
        } catch (IllegalArgumentException ignored) {
            // 유효하지 않은 도메인은 원본 호스트 사용
        }

        // IP 주소 여부
        int hasIpAddress = isIpAddress(hostname) ? 1 : 0;

        // 브랜드 도메인 유사도
        double brandSimilarity = 0.0;

        if (!BRAND_DOMAINS.contains(registeredDomain)) {
            for (String brand : BRAND_DOMAINS) {
                brandSimilarity = Math.max(
                        brandSimilarity,
                        sequenceSimilarity(registeredDomain, brand));
            }
        }

        // 단축 URL 여부
        boolean hasShortener = false;

        for (String shortener : URL_SHORTENERS) {
            if (hostname.equals(shortener)
                    || hostname.endsWith("." + shortener)) {
                hasShortener = true;
                break;
            }
        }

        int digitCount = 0;
        int specialCharCount = 0;

        for (char c : url.toCharArray()) {
            if (Character.isDigit(c)) {
                digitCount++;
            }
            if ("@?=&%_~#".indexOf(c) >= 0) {
                specialCharCount++;
            }
        }

        int suspiciousKeywordCount = 0;
        String lowerUrl = url.toLowerCase(Locale.ROOT);

        for (String keyword : SUSPICIOUS_KEYWORDS) {
            suspiciousKeywordCount += countOccurrences(lowerUrl, keyword);
        }

        Map<String, Float> features = new LinkedHashMap<>();

        features.put("url_length", (float) url.length());
        features.put("hostname_length", (float) hostname.length());
        features.put("domain_length", (float) registeredDomain.length());
        features.put("subdomain_count", (float) subdomainCount);
        features.put("dot_count", (float) countChar(url, '.'));
        features.put("hyphen_count", (float) countChar(url, '-'));
        features.put("digit_count", (float) digitCount);
        features.put("special_char_count", (float) specialCharCount);

        features.put("digit_ratio",
                url.isEmpty() ? 0f : (float) digitCount / url.length());

        features.put("has_ip_address", (float) hasIpAddress);

        features.put("has_https",
                hasExplicitScheme
                        && "https".equalsIgnoreCase(uri.getScheme())
                                ? 1f
                                : 0f);

        features.put("has_at_symbol",
                url.contains("@") ? 1f : 0f);

        features.put("path_length", (float) path.length());

        features.put("path_depth",
                (float) Arrays.stream(path.split("/"))
                        .filter(s -> !s.isEmpty())
                        .count());

        features.put("query_param_count",
                (float) Arrays.stream(query.split("&", -1))
                        .filter(s -> !s.isEmpty())
                        .count());

        features.put("has_punycode",
                hostname.contains("xn--") ? 1f : 0f);

        features.put("suspicious_keyword_count",
                (float) suspiciousKeywordCount);

        features.put("url_entropy", (float) calculateEntropy(url));

        features.put("has_url_shortener",
                hasShortener ? 1f : 0f);

        features.put("brand_similarity", (float) brandSimilarity);

        features.put("scheme_missing",
                hasExplicitScheme ? 0f : 1f);

        return features;
    }

    // ONNX 입력용 float[21] 변환
    public float[] extractFeatureVector(String url) {

        Map<String, Float> features = extractFeatures(url);
        float[] vector = new float[FEATURE_NAMES.size()];

        for (int i = 0; i < FEATURE_NAMES.size(); i++) {
            vector[i] = features.get(FEATURE_NAMES.get(i));
        }

        return vector;
    }

    private int countChar(String text, char target) {
        int count = 0;
        for (char c : text.toCharArray()) {
            if (c == target)
                count++;
        }
        return count;
    }

    private int countOccurrences(String text, String word) {
        int count = 0;
        int index = 0;

        while ((index = text.indexOf(word, index)) >= 0) {
            count++;
            index += word.length();
        }
        return count;
    }

    // Shannon 엔트로피
    private double calculateEntropy(String text) {
        if (text.isEmpty())
            return 0.0;

        Map<Integer, Integer> counts = new HashMap<>();

        text.codePoints().forEach(c -> counts.merge(c, 1, Integer::sum));

        int length = text.codePointCount(0, text.length());
        double entropy = 0.0;

        for (int count : counts.values()) {
            double p = (double) count / length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }

    // 문자열 유사도: Python SequenceMatcher 방식의
    // 연속 일치 블록을 재귀적으로 계산
    private double sequenceSimilarity(String a, String b) {
        if (a.isEmpty() && b.isEmpty())
            return 1.0;

        int matches = matchingSize(
                a, 0, a.length(),
                b, 0, b.length());

        return (2.0 * matches) / (a.length() + b.length());
    }

    private int matchingSize(
            String a, int aStart, int aEnd,
            String b, int bStart, int bEnd) {

        int bestLength = 0;
        int bestA = aStart;
        int bestB = bStart;

        for (int i = aStart; i < aEnd; i++) {
            for (int j = bStart; j < bEnd; j++) {
                int length = 0;

                while (i + length < aEnd
                        && j + length < bEnd
                        && a.charAt(i + length) == b.charAt(j + length)) {
                    length++;
                }

                if (length > bestLength) {
                    bestLength = length;
                    bestA = i;
                    bestB = j;
                }
            }
        }

        if (bestLength == 0)
            return 0;

        return bestLength
                + matchingSize(
                        a, aStart, bestA,
                        b, bStart, bestB)
                + matchingSize(
                        a, bestA + bestLength, aEnd,
                        b, bestB + bestLength, bEnd);
    }

    private boolean isIpAddress(String hostname) {

        // IPv6은 숫자 주소 형태일 때만 확인
        if (hostname.contains(":")) {
            try {
                return InetAddress.getByName(hostname)
                        .getAddress().length == 16;
            } catch (Exception e) {
                return false;
            }
        }

        // IPv4
        if (!hostname.matches("[0-9.]+"))
            return false;

        String[] parts = hostname.split("\\.", -1);
        if (parts.length != 4)
            return false;

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3)
                return false;

            try {
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255)
                    return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }
}
