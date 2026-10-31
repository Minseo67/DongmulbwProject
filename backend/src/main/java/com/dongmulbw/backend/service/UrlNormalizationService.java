
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.UrlNormalizationResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class UrlNormalizationService {

    private static final String NORMALIZATION_VERSION = "norm-v1";
    private static final int MAX_URL_LENGTH = 2048;

    public UrlNormalizationResult normalize(String rawUrl) {

        // 1. 원본 URL 유효성 검증
        if (rawUrl == null || rawUrl.isBlank()
                || rawUrl.length() > MAX_URL_LENGTH) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        // 2. URL 파싱
        URI uri;
        try {
            uri = URI.create(rawUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("INVALID_URL", e);
        }

        // 3. Scheme 및 Host 검증
        String originalScheme = uri.getScheme();
        String originalHost = uri.getHost();

        if (originalScheme == null || originalHost == null
                || originalHost.isBlank()) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        String scheme = originalScheme.toLowerCase(Locale.ROOT);
        String host = originalHost.toLowerCase(Locale.ROOT);

        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        // 4. 포트 검증 및 기본 포트 제거
        int port = uri.getPort();

        if (port < -1 || port > 65535) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        boolean removeDefaultPort = (scheme.equals("http") && port == 80)
                || (scheme.equals("https") && port == 443);

        // 5. 원본 문자열에서 Authority 영역만 수정
        // URI 재조립에 따른 Percent Encoding 변경 방지
        String rawSchemePart = rawUrl.substring(
                0, rawUrl.indexOf(':'));

        int authorityStart = rawSchemePart.length() + 3;

        if (!rawUrl.regionMatches(
                authorityStart - 2, "//", 0, 2)) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        int authorityEnd = rawUrl.length();

        for (char separator : new char[] { '/', '?', '#' }) {
            int index = rawUrl.indexOf(separator, authorityStart);
            if (index >= 0 && index < authorityEnd) {
                authorityEnd = index;
            }
        }

        String authority = rawUrl.substring(
                authorityStart, authorityEnd);

        // 사용자 정보가 포함된 URL은 v1에서 지원하지 않음
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        String normalizedAuthority = authority.toLowerCase(Locale.ROOT);

        // IPv6 주소는 대괄호를 유지
        if (removeDefaultPort) {
            int lastColon = normalizedAuthority.lastIndexOf(':');
            normalizedAuthority = normalizedAuthority.substring(0, lastColon);
        }

        // 6. Path, Query, Fragment는 원본 그대로 보존
        String suffix = rawUrl.substring(authorityEnd);

        String normalizedUrl = scheme + "://" + normalizedAuthority + suffix;

        if (normalizedUrl.length() > MAX_URL_LENGTH) {
            throw new IllegalArgumentException("INVALID_URL");
        }

        // 7. SHA-256 해시 생성
        String urlHash = sha256(normalizedUrl);

        // 8. 정규화 결과 반환
        return new UrlNormalizationResult(
                rawUrl,
                normalizedUrl,
                scheme,
                host,
                urlHash,
                NORMALIZATION_VERSION);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    value.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 algorithm unavailable", e);
        }
    }
}
