
package com.dongmulbw.backend.repository;

import com.dongmulbw.backend.entity.DomainReputation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DomainReputationRepository
        extends JpaRepository<DomainReputation, Long> {

    // 도메인으로 평판 정보 조회
    Optional<DomainReputation> findByDomain(String domain);
}
