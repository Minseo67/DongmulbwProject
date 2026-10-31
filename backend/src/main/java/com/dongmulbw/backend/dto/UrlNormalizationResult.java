
package com.dongmulbw.backend.dto;

public record UrlNormalizationResult(
        String rawUrl,
        String normalizedUrl,
        String scheme,
        String domain,
        String urlHash,
        String normalizationVersion) {
}
