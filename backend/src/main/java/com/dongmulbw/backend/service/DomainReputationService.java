
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.entity.DomainReputation;
import com.dongmulbw.backend.repository.DomainReputationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;

@Service
public class DomainReputationService {

    private final DomainReputationRepository repository;

    public DomainReputationService(
            DomainReputationRepository repository) {
        this.repository = repository;
    }

    public enum ReputationStatus {
        BLACKLISTED,
        WHITELISTED,
        UNKNOWN,
        EXPIRED
    }

    @Transactional(readOnly = true)
    public ReputationStatus checkDomain(String domain) {

        if (domain == null || domain.isBlank()) {
            return ReputationStatus.UNKNOWN;
        }

        String normalizedDomain = domain.trim()
                .toLowerCase(Locale.ROOT);

        Optional<DomainReputation> result = repository.findByDomain(normalizedDomain);

        if (result.isEmpty()) {
            return ReputationStatus.UNKNOWN;
        }

        DomainReputation reputation = result.get();

        LocalDateTime expiresAt = reputation.getExpiresAt();

        if (expiresAt != null
                && !expiresAt.isAfter(LocalDateTime.now())) {
            return ReputationStatus.EXPIRED;
        }

        if (Boolean.TRUE.equals(reputation.getBlacklisted())) {
            return ReputationStatus.BLACKLISTED;
        }

        if (Boolean.TRUE.equals(reputation.getWhitelisted())) {
            return ReputationStatus.WHITELISTED;
        }

        return ReputationStatus.UNKNOWN;
    }
}
