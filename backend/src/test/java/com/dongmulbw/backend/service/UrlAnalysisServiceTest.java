
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UrlAnalysisServiceTest {

        private RuleBasedAnalysisService ruleBasedAnalysisService;
        private DomainReputationService domainReputationService;
        private PhishingUrlService phishingUrlService;
        private UrlAnalysisService urlAnalysisService;

        @BeforeEach
        void setUp() {
                // 외부 서비스와 DB 조회를 실제 실행하지 않도록 Mock 객체 생성
                ruleBasedAnalysisService = mock(RuleBasedAnalysisService.class);
                domainReputationService = mock(DomainReputationService.class);
                phishingUrlService = mock(PhishingUrlService.class);

                urlAnalysisService = new UrlAnalysisService(
                                ruleBasedAnalysisService,
                                domainReputationService,
                                phishingUrlService);
        }

        /**
         * 테스트용 규칙 분석 결과 생성
         * 실제 규칙 탐지를 실행하지 않고 원하는 점수를 지정한다.
         */
        private RuleAnalysisResult createRuleResult(double score) {
                String level = score >= 60 ? "DANGER"
                                : score >= 30 ? "WARNING" : "SAFE";

                return new RuleAnalysisResult(
                                10, 0, 1, 0,
                                false, false, false, false,
                                false, false, false, 0,
                                score, level, List.of());
        }

        /**
         * 특정 URL에 대한 규칙 점수와 도메인 평판을 설정한다.
         */
        private void prepareAnalysis(
                        String url,
                        String domain,
                        double score,
                        DomainReputationService.ReputationStatus status) {

                when(ruleBasedAnalysisService.extract(url, domain))
                                .thenReturn(createRuleResult(score));

                when(domainReputationService.checkDomain(domain))
                                .thenReturn(status);
        }

        @Test
        void blacklistForcesRuleScoreTo100() {
                String url = "http://malicious.example/login";
                String domain = "malicious.example";

                prepareAnalysis(url, domain, 20,
                                DomainReputationService.ReputationStatus.BLACKLISTED);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 블랙리스트는 기존 규칙 점수와 관계없이 100점
                assertEquals(100.0, result.ruleResult().suspiciousScore());
                assertEquals("DANGER", result.ruleResult().riskLevel());
                assertEquals(
                                DomainReputationService.ReputationStatus.BLACKLISTED,
                                result.reputationStatus());
        }

        @Test
        void whitelistDeducts10FromRuleScore() {
                String url = "https://trusted.example/home";
                String domain = "trusted.example";

                prepareAnalysis(url, domain, 65,
                                DomainReputationService.ReputationStatus.WHITELISTED);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 화이트리스트는 규칙 점수에서만 10점 차감
                assertEquals(55.0, result.ruleResult().suspiciousScore());
                assertEquals("WARNING", result.ruleResult().riskLevel());
        }

        @Test
        void whitelistScoreCannotBecomeNegative() {
                String url = "https://trusted.example/";
                String domain = "trusted.example";

                prepareAnalysis(url, domain, 5,
                                DomainReputationService.ReputationStatus.WHITELISTED);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 10점을 차감하더라도 최저 점수는 0점
                assertEquals(0.0, result.ruleResult().suspiciousScore());
                assertEquals("SAFE", result.ruleResult().riskLevel());
        }

        @Test
        void expiredWhitelistDoesNotDeductScore() {
                String url = "https://expired.example/";
                String domain = "expired.example";

                prepareAnalysis(url, domain, 65,
                                DomainReputationService.ReputationStatus.EXPIRED);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 만료된 화이트리스트는 원래 규칙 점수 유지
                assertEquals(65.0, result.ruleResult().suspiciousScore());
                assertEquals("DANGER", result.ruleResult().riskLevel());
        }

        @Test
        void unknownDomainKeepsRuleScore() {
                String url = "https://unknown.example/path";
                String domain = "unknown.example";

                prepareAnalysis(url, domain, 35,
                                DomainReputationService.ReputationStatus.UNKNOWN);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 평판 정보가 없으면 기존 분석 결과 유지
                assertEquals(35.0, result.ruleResult().suspiciousScore());
                assertEquals("WARNING", result.ruleResult().riskLevel());
        }

        @Test
        void phishingUrlMatchReturnsTrue() {
                String url = "https://phishing-test.invalid/login";
                String domain = "phishing-test.invalid";

                prepareAnalysis(url, domain, 40,
                                DomainReputationService.ReputationStatus.UNKNOWN);

                when(phishingUrlService.isPhishingUrl(url))
                                .thenReturn(true);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 피싱 URL 목록에 존재하면 true 반환
                assertTrue(result.phishingUrlMatched());
        }

        @Test
        void phishingUrlNotMatchedReturnsFalse() {
                String url = "https://example.com/";
                String domain = "example.com";

                prepareAnalysis(url, domain, 10,
                                DomainReputationService.ReputationStatus.UNKNOWN);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 피싱 URL 목록에 없으면 false 반환
                assertFalse(result.phishingUrlMatched());
        }

        @Test
        void normalizedUrlMatchReturnsTrueWhenRawUrlDoesNotMatch() {
                String rawUrl = "HTTPS://example.com/login";
                String normalizedUrl = "https://example.com/login";
                String domain = "example.com";

                prepareAnalysis(rawUrl, domain, 20,
                                DomainReputationService.ReputationStatus.UNKNOWN);

                when(phishingUrlService.isPhishingUrl(rawUrl))
                                .thenReturn(false);
                when(phishingUrlService.isPhishingUrl(normalizedUrl))
                                .thenReturn(true);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(rawUrl, normalizedUrl, domain);

                // 원본 URL이 불일치해도 정규화 URL이 일치하면 탐지
                assertTrue(result.phishingUrlMatched());

                verify(phishingUrlService).isPhishingUrl(rawUrl);
                verify(phishingUrlService).isPhishingUrl(normalizedUrl);
        }

        /**
         * 동일한 화이트리스트 URL을 반복 분석해도
         * 규칙 기반 위험 점수의 감점이 누적되지 않는지 검증한다.
         */
        @Test
        void whitelistDeductionIsNotAccumulated() {
                // 테스트 대상 URL 및 도메인
                String url = "https://trusted.example/home";
                String domain = "trusted.example";

                // 규칙 기반 원본 점수 65점, 화이트리스트 상태 설정
                prepareAnalysis(
                                url,
                                domain,
                                65.0,
                                DomainReputationService.ReputationStatus.WHITELISTED);

                // 동일한 URL을 연속으로 세 번 분석
                UrlAnalysisService.AnalysisResult first = urlAnalysisService.analyze(url, url, domain);

                UrlAnalysisService.AnalysisResult second = urlAnalysisService.analyze(url, url, domain);

                UrlAnalysisService.AnalysisResult third = urlAnalysisService.analyze(url, url, domain);

                // 매번 원본 점수 65점에서 10점만 차감해야 함
                assertEquals(55.0, first.ruleResult().suspiciousScore());
                assertEquals(55.0, second.ruleResult().suspiciousScore());
                assertEquals(55.0, third.ruleResult().suspiciousScore());

                // 감점 후 위험 등급도 세 번 모두 동일해야 함
                assertEquals("WARNING", first.ruleResult().riskLevel());
                assertEquals("WARNING", second.ruleResult().riskLevel());
                assertEquals("WARNING", third.ruleResult().riskLevel());

                // 규칙 분석과 평판 조회가 각각 세 번 수행되었는지 검증
                verify(ruleBasedAnalysisService, times(3))
                                .extract(url, domain);

                verify(domainReputationService, times(3))
                                .checkDomain(domain);
        }

        /**
         * 화이트리스트 도메인이라도 피싱 URL 목록에 등록된 경우
         * 규칙 점수 10점 할인이 적용되지 않는지 검증한다.
         */
        @Test
        void phishingUrlMatchPreventsWhitelistDeduction() {
                String url = "https://trusted.example/phishing";
                String domain = "trusted.example";

                // 원래 규칙 점수 65점, 도메인은 화이트리스트
                prepareAnalysis(
                                url,
                                domain,
                                65.0,
                                DomainReputationService.ReputationStatus.WHITELISTED);

                // 피싱 URL 데이터셋에 등록된 URL이라고 가정
                when(phishingUrlService.isPhishingUrl(url))
                                .thenReturn(true);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(url, url, domain);

                // 피싱 URL이므로 화이트리스트 감점 없이 65점 유지
                assertEquals(65.0, result.ruleResult().suspiciousScore());
                assertEquals("DANGER", result.ruleResult().riskLevel());

                // 피싱 URL 탐지 결과와 도메인 평판 상태 확인
                assertTrue(result.phishingUrlMatched());
                assertEquals(
                                DomainReputationService.ReputationStatus.WHITELISTED,
                                result.reputationStatus());
        }

        /**
         * 원본 URL은 피싱 목록과 일치하지 않더라도
         * 정규화 URL이 일치하면 화이트리스트 할인을 제외한다.
         */
        @Test
        void normalizedPhishingUrlPreventsWhitelistDeduction() {
                String rawUrl = "HTTPS://trusted.example/phishing";
                String normalizedUrl = "https://trusted.example/phishing";
                String domain = "trusted.example";

                // 원래 규칙 점수 40점, 도메인은 화이트리스트
                prepareAnalysis(
                                rawUrl,
                                domain,
                                40.0,
                                DomainReputationService.ReputationStatus.WHITELISTED);

                when(phishingUrlService.isPhishingUrl(rawUrl))
                                .thenReturn(false);

                when(phishingUrlService.isPhishingUrl(normalizedUrl))
                                .thenReturn(true);

                UrlAnalysisService.AnalysisResult result = urlAnalysisService.analyze(
                                rawUrl,
                                normalizedUrl,
                                domain);

                // 정규화 URL이 피싱 목록에 있으므로 원래 점수 유지
                assertEquals(40.0, result.ruleResult().suspiciousScore());
                assertEquals("WARNING", result.ruleResult().riskLevel());
                assertTrue(result.phishingUrlMatched());

                // 원본 URL과 정규화 URL을 모두 검사했는지 확인
                verify(phishingUrlService).isPhishingUrl(rawUrl);
                verify(phishingUrlService).isPhishingUrl(normalizedUrl);
        }

}
