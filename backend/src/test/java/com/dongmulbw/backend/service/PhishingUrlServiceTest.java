
package com.dongmulbw.backend.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PhishingUrlServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void phishingUrlLookupTest() throws Exception {

        // 1. 테스트용 피싱 URL 목록 생성
        Path testFile = tempDir.resolve("phishing_test.txt");

        Files.writeString(
                testFile,
                "https://phishing-test.invalid/login\n"
                        + "http://fake-test.invalid/verify\n",
                StandardCharsets.UTF_8);

        // 2. 서비스 생성 및 테스트 파일 경로 지정
        PhishingUrlService service = new PhishingUrlService();

        ReflectionTestUtils.setField(
                service,
                "feedPath",
                testFile.toString());

        // 3. 피싱 URL 목록 로드
        service.loadPhishingUrls();

        // 4. 로드된 URL 개수 확인
        assertEquals(2, service.getLoadedUrlCount());

        // 5. 등록된 URL 탐지
        assertTrue(
                service.isPhishingUrl(
                        "https://phishing-test.invalid/login"));

        // 6. 등록되지 않은 URL은 미일치
        assertFalse(
                service.isPhishingUrl(
                        "https://example.com/"));

        // 7. null 및 빈 문자열 처리
        assertFalse(service.isPhishingUrl(null));
        assertFalse(service.isPhishingUrl(""));

        System.out.println("PhishingUrlService 테스트 성공");
    }

    @Test
    void loadActualPhishingUrlsTest() {

        PhishingUrlService service = new PhishingUrlService();

        Path actualFile = Path.of(
                "..", "ml", "data", "phishing_urls_combined.txt").toAbsolutePath().normalize();

        assertTrue(
                Files.isRegularFile(actualFile),
                "피싱 URL 파일을 찾을 수 없습니다: " + actualFile);

        ReflectionTestUtils.setField(
                service,
                "feedPath",
                actualFile.toString());

        service.loadPhishingUrls();

        assertEquals(
                52119,
                service.getLoadedUrlCount(),
                "로드된 피싱 URL 개수가 예상과 다릅니다.");

        System.out.println(
                "실제 피싱 URL 로드 성공: "
                        + service.getLoadedUrlCount() + "개");
    }

    @Test
    void actualFeedUrlLookupTest() throws Exception {

        Path actualFile = Path.of(
                "..", "ml", "data", "phishing_urls_combined.txt").toAbsolutePath().normalize();

        assertTrue(Files.isRegularFile(actualFile));

        PhishingUrlService service = new PhishingUrlService();

        ReflectionTestUtils.setField(
                service,
                "feedPath",
                actualFile.toString());

        service.loadPhishingUrls();

        // 실제 파일에 등록된 첫 번째 URL을 읽음
        String firstUrl;

        try (var lines = Files.lines(actualFile, StandardCharsets.UTF_8)) {
            firstUrl = lines
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .findFirst()
                    .orElseThrow();
        }

        // 등록된 URL은 true
        assertTrue(service.isPhishingUrl(firstUrl));

        // 등록되지 않은 테스트용 URL은 false
        assertFalse(
                service.isPhishingUrl(
                        "https://not-in-feed-test.invalid/"));

        System.out.println("실제 피싱 URL 조회 테스트 성공");
    }

}
