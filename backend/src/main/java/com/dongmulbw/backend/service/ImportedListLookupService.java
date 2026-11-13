
package com.dongmulbw.backend.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

@Service
public class ImportedListLookupService {

    private final JdbcTemplate jdbcTemplate;

    public ImportedListLookupService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean isWhitelisted(String domain) {
        if (domain == null || domain.isBlank()) {
            return false;
        }

        String normalizedDomain =
                domain.trim().toLowerCase(Locale.ROOT);

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM domain_whitelist WHERE domain = ?",
                Integer.class,
                normalizedDomain
        );

        return count != null && count > 0;
    }

    public boolean isBlacklisted(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

        String candidate = url.trim();
        byte[] hash = sha256(candidate);

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM url_blacklist "
                        + "WHERE url_hash = ? AND url = ?",
                Integer.class,
                hash,
                candidate
        );

        return count != null && count > 0;
    }

    private byte[] sha256(String value) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            return digest.digest(
                    value.getBytes(StandardCharsets.UTF_8)
            );

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 알고리즘을 사용할 수 없습니다.", e
            );
        }
    }
}
