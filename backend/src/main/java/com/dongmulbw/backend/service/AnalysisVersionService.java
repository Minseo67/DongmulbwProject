
package com.dongmulbw.backend.service;

import org.springframework.stereotype.Service;

@Service
public class AnalysisVersionService {

    // 블랙리스트 규칙 점수 100점 + RF 7:3 정책 반영
    private static final String RULE_VERSION = "v2";

    // MlAnalysisService에서 사용하는 실제 모델 버전
    private static final String MODEL_VERSION = "G-V6-A-31";

    public String getRuleVersion() {
        return RULE_VERSION;
    }

    public String getModelVersion() {
        return MODEL_VERSION;
    }
}
