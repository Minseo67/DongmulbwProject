
package com.dongmulbw.backend.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

@Service
public class PhishingUrlService {

    private final Set<String> phishingUrls = new HashSet<>();

    @Value("${phishing.feed.path:../ml/data/phishing_urls_combined.txt}")
    private String feedPath;

    @PostConstruct
    public void loadPhishingUrls() {
        Path path = Path.of(feedPath);

        if (!Files.isRegularFile(path)) {
            System.out.println("[PhishingUrlService] 파일을 찾을 수 없습니다: "
                    + path.toAbsolutePath());
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(
                path, StandardCharsets.UTF_8)) {

            String line;

            while ((line = reader.readLine()) != null) {
                String url = line.trim();

                if (!url.isEmpty()) {
                    phishingUrls.add(url);
                }
            }

            System.out.println("[PhishingUrlService] 로드된 URL: "
                    + phishingUrls.size());

        } catch (IOException e) {
            throw new IllegalStateException(
                    "피싱 URL 목록을 읽지 못했습니다.", e);
        }
    }

    public boolean isPhishingUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

        return phishingUrls.contains(url.trim());
    }

    public int getLoadedUrlCount() {
        return phishingUrls.size();
    }
}
