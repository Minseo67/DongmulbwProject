
package com.dongmulbw.backend.repository;

import com.dongmulbw.backend.entity.UrlAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UrlAnalysisRepository
        extends JpaRepository<UrlAnalysis, Long> {

    // URL ID로 기존 분석 결과 조회
    Optional<UrlAnalysis> findByUrlId(Long urlId);

    // 분석 결과 토큰으로 조회
    Optional<UrlAnalysis> findByResultToken(String resultToken);
}
