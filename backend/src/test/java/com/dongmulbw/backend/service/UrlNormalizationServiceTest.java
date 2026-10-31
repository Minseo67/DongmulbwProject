
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.UrlNormalizationResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class UrlNormalizationServiceTest {

    private final UrlNormalizationService service = new UrlNormalizationService();

    @Test
    void schemeHostAndDefaultPort() {
        UrlNormalizationResult result = service.normalize("HTTPS://Example.COM:443/login");

        assertEquals("https://example.com/login",
                result.normalizedUrl());
        assertEquals("https", result.scheme());
        assertEquals("example.com", result.domain());
        assertEquals("norm-v1", result.normalizationVersion());
    }

    @Test
    void preservePathQueryAndFragment() {
        String url = "https://Example.COM/Admin?b=2&a=1#section";

        UrlNormalizationResult result = service.normalize(url);

        assertEquals(
                "https://example.com/Admin?b=2&a=1#section",
                result.normalizedUrl());
        assertEquals(url, result.rawUrl());
    }

    @Test
    void preserveNonDefaultPortAndEncoding() {
        UrlNormalizationResult result = service.normalize("https://EXAMPLE.com:8443/a%2Fb");

        assertEquals("https://example.com:8443/a%2Fb",
                result.normalizedUrl());
    }

    @Test
    void normalizeIpv6() {
        UrlNormalizationResult result = service.normalize("https://[::1]:443/login");

        assertEquals("https://[::1]/login",
                result.normalizedUrl());
    }

    @Test
    void rejectInvalidUrls() {
        String[] invalidUrls = {
                "",
                "ftp://example.com/file",
                "https:///login",
                "https://example.com/a b",
                "https://example.com:abc/login",
                "https://example.com:99999/login"
        };

        for (String url : invalidUrls) {
            assertThrows(IllegalArgumentException.class,
                    () -> service.normalize(url),
                    "거부되어야 하는 URL: " + url);
        }
    }

    @Test
    void sameNormalizedUrlProducesSameHash() {
        UrlNormalizationResult first = service.normalize("HTTPS://Example.COM:443/login");

        UrlNormalizationResult second = service.normalize("https://example.com/login");

        assertEquals(first.normalizedUrl(), second.normalizedUrl());
        assertEquals(first.urlHash(), second.urlHash());
        assertEquals(64, first.urlHash().length());
    }

    @Test
    void hashMatchesSha256() throws Exception {
        UrlNormalizationResult result = service.normalize("https://example.com/login");

        byte[] expectedBytes = MessageDigest
                .getInstance("SHA-256")
                .digest(result.normalizedUrl()
                        .getBytes(StandardCharsets.UTF_8));

        String expectedHash = HexFormat.of().formatHex(expectedBytes);

        assertEquals(expectedHash, result.urlHash());
    }
}
