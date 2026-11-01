
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.repository.DomainReputationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.dongmulbw.backend.entity.DomainReputation;
import java.time.LocalDateTime;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class DomainReputationServiceTest {

    private DomainReputationRepository repository;
    private DomainReputationService service;

    @BeforeEach
    void setUp() {
        repository = mock(DomainReputationRepository.class);
        service = new DomainReputationService(repository);
    }

    @Test
    void unknownDomainReturnsUnknown() {
        when(repository.findByDomain("example.com"))
                .thenReturn(Optional.empty());

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                service.checkDomain("example.com"));

        verify(repository).findByDomain("example.com");
    }

    @Test
    void domainIsNormalizedBeforeLookup() {
        when(repository.findByDomain("example.com"))
                .thenReturn(Optional.empty());

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                service.checkDomain("  EXAMPLE.COM  "));

        verify(repository).findByDomain("example.com");
    }

    @Test
    void nullDomainReturnsUnknown() {
        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                service.checkDomain(null));

        verifyNoInteractions(repository);
    }

    @Test
    void blankDomainReturnsUnknown() {
        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                service.checkDomain("   "));

        verifyNoInteractions(repository);
    }

    @Test
    void blacklistedDomainReturnsBlacklisted() {
        DomainReputation reputation = mock(DomainReputation.class);

        when(repository.findByDomain("malicious.example"))
                .thenReturn(Optional.of(reputation));

        when(reputation.getExpiresAt()).thenReturn(null);
        when(reputation.getBlacklisted()).thenReturn(true);

        assertEquals(
                DomainReputationService.ReputationStatus.BLACKLISTED,
                service.checkDomain("malicious.example"));
    }

    @Test
    void whitelistedDomainReturnsWhitelisted() {
        DomainReputation reputation = mock(DomainReputation.class);

        when(repository.findByDomain("trusted.example"))
                .thenReturn(Optional.of(reputation));

        when(reputation.getExpiresAt()).thenReturn(null);
        when(reputation.getBlacklisted()).thenReturn(false);
        when(reputation.getWhitelisted()).thenReturn(true);

        assertEquals(
                DomainReputationService.ReputationStatus.WHITELISTED,
                service.checkDomain("trusted.example"));
    }

    @Test
    void expiredDomainReturnsExpired() {
        DomainReputation reputation = mock(DomainReputation.class);

        when(repository.findByDomain("expired.example"))
                .thenReturn(Optional.of(reputation));

        when(reputation.getExpiresAt())
                .thenReturn(LocalDateTime.now().minusDays(1));

        assertEquals(
                DomainReputationService.ReputationStatus.EXPIRED,
                service.checkDomain("expired.example"));
    }

}
