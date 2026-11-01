
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.dto.RuleAnalysisResult;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class RuleAnalysisJsonService {

    private final ObjectMapper objectMapper;

    public RuleAnalysisJsonService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String toJson(RuleAnalysisResult result) {

        if (result == null) {
            throw new IllegalArgumentException(
                    "규칙 기반 분석 결과가 null입니다.");
        }

        Map<String, Object> findings = new LinkedHashMap<>();

        // 1. 도메인 길이
        findings.put("domainLength", result.domainLength());

        // 2. 하이픈 개수
        findings.put("hyphenCount", result.hyphenCount());

        // 3. 점(.) 개수
        findings.put("dotCount", result.dotCount());

        // 4. 숫자 개수
        findings.put("digitCount", result.digitCount());

        // 5. IP 주소 사용 여부
        findings.put("hasIpAddress", result.hasIpAddress());

        // 6. Punycode 사용 여부
        findings.put("hasPunycode", result.hasPunycode());

        // 7. 의심 키워드 포함 여부
        findings.put(
                "hasSuspiciousKeyword",
                result.hasSuspiciousKeyword());

        // 8. 의심 TLD 사용 여부
        findings.put(
                "hasSuspiciousTld",
                result.hasSuspiciousTld());

        // 9. 브랜드 사칭 여부
        findings.put(
                "hasBrandImpersonation",
                result.hasBrandImpersonation());

        // 10. 서브도메인 브랜드 사칭 여부
        findings.put(
                "hasSubdomainBrandImpersonation",
                result.hasSubdomainBrandImpersonation());

        // 11. 단축 URL 서비스 사용 여부
        findings.put(
                "hasShortUrlService",
                result.hasShortUrlService());

        // 규칙 기반 탐지 점수
        findings.put(
                "suspiciousScore",
                result.suspiciousScore());

        try {
            return objectMapper.writeValueAsString(findings);
        } catch (JacksonException e) {
            throw new IllegalStateException(
                    "규칙 기반 분석 결과 JSON 변환 실패",
                    e);
        }
    }
}
