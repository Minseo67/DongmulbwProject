package com.dongmulbw.backend.service;

import com.google.common.net.InternetDomainName;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UrlFeatureExtractor {
    private static final List<String> NAMES = List.of(
        "url_length", "domain_length", "subdomain_count", "dot_count", "hyphen_count",
        "digit_count", "special_char_count", "digit_ratio", "has_ip_address", "has_at_symbol",
        "path_length", "path_depth", "query_param_count", "has_punycode",
        "suspicious_keyword_count", "url_entropy", "has_url_shortener", "brand_similarity",
        "hostname_entropy", "subdomain_length", "has_port", "percent_encoded_count",
        "query_length", "has_encoded_url", "suspicious_file_extension", "has_path",
        "has_query", "hostname_digit_ratio", "path_entropy", "max_subdomain_length",
        "hostname_hyphen_count"
    );
    private static final List<String> KEYWORDS = List.of(
        "login", "verify", "account", "secure", "update", "confirm", "password",
        "signin", "bank", "payment"
    );
    private static final Set<String> SHORTENERS = Set.of(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rebrand.ly"
    );
    private static final List<String> BRANDS = List.of(
        "google.com", "naver.com", "kakao.com", "youtube.com", "facebook.com",
        "instagram.com", "amazon.com", "microsoft.com", "apple.com", "paypal.com"
    );
    private static final Set<String> EXTENSIONS = Set.of(
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
        ".msi", ".apk", ".hta"
    );
    private static final Pattern PERCENT = Pattern.compile("%[0-9A-Fa-f]{2}");
    private static final Pattern ENCODED_URL = Pattern.compile("https?%3a%2f%2f", Pattern.CASE_INSENSITIVE);

    public String normalizeV2(String value) {
        if (value == null) return "";
        String url = value.strip();
        if (url.isEmpty()) return "";
        if (url.startsWith("//")) url = url.substring(2);
        int scheme = url.indexOf("://");
        if (scheme >= 0) url = url.substring(scheme + 3);
        try {
            URI parsed = URI.create("//" + url);
            String host = rawAuthority(parsed).toLowerCase(Locale.ROOT);
            if (host.startsWith("www.")) host = host.substring(4);
            String path = orEmpty(parsed.getRawPath());
            if (path.equals("/")) path = "";
            String result = host + path;
            if (parsed.getRawQuery() != null && !parsed.getRawQuery().isEmpty()) result += "?" + parsed.getRawQuery();
            if (parsed.getRawFragment() != null && !parsed.getRawFragment().isEmpty()) result += "#" + parsed.getRawFragment();
            return result;
        } catch (IllegalArgumentException ex) {
            return url;
        }
    }

    public Map<String, Float> extractFeatures(String originalUrl) {
        if (originalUrl == null || originalUrl.isBlank()) throw new IllegalArgumentException("INVALID_URL");
        String url = normalizeV2(originalUrl);
        URI parsed;
        try {
            parsed = URI.create("http://" + url);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("INVALID_URL", ex);
        }
        String hostname = orEmpty(parsed.getHost()).toLowerCase(Locale.ROOT);
        String path = orEmpty(parsed.getRawPath());
        String query = orEmpty(parsed.getRawQuery());
        String authority = rawAuthority(parsed).toLowerCase(Locale.ROOT);

        String registered = hostname;
        String subdomain = "";
        int subdomainCount = 0;
        try {
            InternetDomainName domain = InternetDomainName.from(hostname);
            if (domain.isUnderPublicSuffix()) {
                registered = domain.topPrivateDomain().toString();
                if (hostname.length() > registered.length()) {
                    subdomain = hostname.substring(0, hostname.length() - registered.length() - 1);
                    subdomainCount = subdomain.split("\\.", -1).length;
                }
            }
        } catch (IllegalArgumentException ignored) {
            // Python tldextract and Guava may disagree on some suffixes.
        }

        int digits = digitCount(url);
        double brandSimilarity = 0;
        if (!BRANDS.contains(registered)) {
            for (String brand : BRANDS) brandSimilarity = Math.max(brandSimilarity, sequenceRatio(registered, brand));
        }
        boolean shortener = SHORTENERS.contains(hostname)
            || SHORTENERS.stream().anyMatch(s -> hostname.endsWith("." + s));
        int keywordCount = 0;
        String lower = url.toLowerCase(Locale.ROOT);
        for (String keyword : KEYWORDS) keywordCount += occurrences(lower, keyword);
        String filename = path.substring(path.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
        boolean suspiciousExtension = EXTENSIONS.stream().anyMatch(filename::endsWith);
        int percentCount = 0;
        Matcher matcher = PERCENT.matcher(url);
        while (matcher.find()) percentCount++;
        int queryParams = 0;
        if (!query.isEmpty()) {
            for (String part : query.split("&", -1)) {
                if (!part.isEmpty()) queryParams++;
            }
        }
        String hostnameWithoutPort = authority.split(":", -1)[0];
        String[] parts = hostnameWithoutPort.split("\\.", -1);
        int maxSubdomainLength = 0;
        for (int i = 0; i < parts.length - 2; i++) {
            maxSubdomainLength = Math.max(maxSubdomainLength, parts[i].length());
        }
        int portPresent = 0;
        try { portPresent = parsed.getPort() >= 0 ? 1 : 0; }
        catch (Exception ignored) { /* malformed port */ }

        Map<String, Float> values = new LinkedHashMap<>();
        values.put("url_length", (float) url.length());
        values.put("domain_length", (float) registered.length());
        values.put("subdomain_count", (float) subdomainCount);
        values.put("dot_count", (float) occurrences(url, "."));
        values.put("hyphen_count", (float) occurrences(url, "-"));
        values.put("digit_count", (float) digits);
        values.put("special_char_count", (float) url.chars().filter(c -> "@?=&%_~#".indexOf(c) >= 0).count());
        values.put("digit_ratio", url.isEmpty() ? 0f : (float) digits / url.length());
        values.put("has_ip_address", isIpAddress(hostname) ? 1f : 0f);
        values.put("has_at_symbol", url.contains("@") ? 1f : 0f);
        values.put("path_length", (float) path.length());
        values.put("path_depth", (float) Arrays.stream(path.split("/", -1)).filter(s -> !s.isEmpty()).count());
        values.put("query_param_count", (float) queryParams);
        values.put("has_punycode", hostname.contains("xn--") ? 1f : 0f);
        values.put("suspicious_keyword_count", (float) keywordCount);
        values.put("url_entropy", (float) entropy(url));
        values.put("has_url_shortener", shortener ? 1f : 0f);
        values.put("brand_similarity", (float) brandSimilarity);
        values.put("hostname_entropy", (float) entropy(hostname));
        values.put("subdomain_length", (float) subdomain.length());
        values.put("has_port", (float) portPresent);
        values.put("percent_encoded_count", (float) percentCount);
        values.put("query_length", (float) query.length());
        values.put("has_encoded_url", ENCODED_URL.matcher(url).find() ? 1f : 0f);
        values.put("suspicious_file_extension", suspiciousExtension ? 1f : 0f);
        values.put("has_path", path.isEmpty() ? 0f : 1f);
        values.put("has_query", query.isEmpty() ? 0f : 1f);
        values.put("hostname_digit_ratio", hostnameWithoutPort.isEmpty() ? 0f :
            (float) digitCount(hostnameWithoutPort) / hostnameWithoutPort.length());
        values.put("path_entropy", (float) entropy(path));
        values.put("max_subdomain_length", (float) maxSubdomainLength);
        values.put("hostname_hyphen_count", (float) occurrences(hostnameWithoutPort, "-"));
        return values;
    }

    public float[] extractFeatureVector(String url) {
        Map<String, Float> values = extractFeatures(url);
        float[] vector = new float[NAMES.size()];
        for (int i = 0; i < NAMES.size(); i++) vector[i] = values.get(NAMES.get(i));
        return vector;
    }

    private static String orEmpty(String s) { return s == null ? "" : s; }
    private static String rawAuthority(URI uri) { return orEmpty(uri.getRawAuthority()); }
    private static int occurrences(String text, String needle) {
        int count = 0, from = 0;
        while ((from = text.indexOf(needle, from)) >= 0) { count++; from += needle.length(); }
        return count;
    }
    private static int digitCount(String s) { return (int) s.codePoints().filter(Character::isDigit).count(); }
    private static double entropy(String text) {
        if (text.isEmpty()) return 0;
        Map<Integer, Integer> counts = new HashMap<>();
        text.codePoints().forEach(cp -> counts.merge(cp, 1, Integer::sum));
        double n = text.codePointCount(0, text.length());
        double result = 0;
        for (int count : counts.values()) { double p = count / n; result -= p * (Math.log(p) / Math.log(2)); }
        return result;
    }
    private static boolean isIpAddress(String host) {
        if (host.matches("[0-9.]+")) {
            String[] parts = host.split("\\.", -1);
            if (parts.length != 4) return false;
            for (String part : parts) {
                try { if (part.isEmpty() || Integer.parseInt(part) > 255 || Integer.parseInt(part) < 0) return false; }
                catch (NumberFormatException ex) { return false; }
            }
            return true;
        }
        if (!host.contains(":")) return false;
        try { return InetAddress.getByName(host).getAddress().length == 16; }
        catch (Exception ex) { return false; }
    }
    // Approximation of Python difflib.SequenceMatcher; exact tie-breaking may differ.
    private static double sequenceRatio(String a, String b) {
        if (a.isEmpty() && b.isEmpty()) return 1;
        return (2.0 * matchingSize(a, 0, a.length(), b, 0, b.length())) / (a.length() + b.length());
    }
    private static int matchingSize(String a, int as, int ae, String b, int bs, int be) {
        int best = 0, ai = as, bi = bs;
        for (int i = as; i < ae; i++) for (int j = bs; j < be; j++) {
            int n = 0;
            while (i + n < ae && j + n < be && a.charAt(i + n) == b.charAt(j + n)) n++;
            if (n > best) { best = n; ai = i; bi = j; }
        }
        if (best == 0) return 0;
        return best + matchingSize(a, as, ai, b, bs, bi) + matchingSize(a, ai + best, ae, b, bi + best, be);
    }
}
