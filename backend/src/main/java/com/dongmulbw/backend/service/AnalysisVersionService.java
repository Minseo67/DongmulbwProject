
package com.dongmulbw.backend.service;

import org.springframework.stereotype.Service;

@Service
public class AnalysisVersionService {

    // 현재 규칙 기반 분석 버전
    private static final String RULE_VERSION = "v1";

    // 현재 Random Forest 모델 버전
    private static final String MODEL_VERSION = "rf_f_v1";

    // 현재 버전 조회
    public String getRuleVersion() {
        return RULE_VERSION;
    }

    public String getModelVersion() {
        return MODEL_VERSION;
    }
}
