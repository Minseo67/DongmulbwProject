
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

        /**
         * 만료된 블랙리스트는 BLACKLISTED가 아닌 EXPIRED를 반환해야 한다.
         */
        @Test
        void expiredBlacklistReturnsExpired() {
                // 만료 시간이 지난 블랙리스트 데이터 생성
                DomainReputation reputation = mock(DomainReputation.class);

                when(repository.findByDomain("blocked.example"))
                                .thenReturn(Optional.of(reputation));

                when(reputation.getExpiresAt())
                                .thenReturn(LocalDateTime.now().minusMinutes(1));

                when(reputation.getBlacklisted()).thenReturn(true);

                // 만료된 블랙리스트는 위험도 100점 강제 대상에서 제외
                assertEquals(
                                DomainReputationService.ReputationStatus.EXPIRED,
                                service.checkDomain("blocked.example"));
        }

        /**
         * 만료된 화이트리스트는 WHITELISTED가 아닌 EXPIRED를 반환해야 한다.
         */
        @Test
        void expiredWhitelistReturnsExpired() {
                // 만료 시간이 지난 화이트리스트 데이터 생성
                DomainReputation reputation = mock(DomainReputation.class);

                when(repository.findByDomain("trusted.example"))
                                .thenReturn(Optional.of(reputation));

                when(reputation.getExpiresAt())
                                .thenReturn(LocalDateTime.now().minusMinutes(1));

                when(reputation.getWhitelisted()).thenReturn(true);

                // 만료된 화이트리스트는 규칙 점수 -10점을 적용하지 않음
                assertEquals(
                                DomainReputationService.ReputationStatus.EXPIRED,
                                service.checkDomain("trusted.example"));
        }

        /**
         * 만료 시간이 미래라면 화이트리스트 상태를 유지해야 한다.
         */
        @Test
        void activeWhitelistReturnsWhitelisted() {
                DomainReputation reputation = mock(DomainReputation.class);

                when(repository.findByDomain("active.example"))
                                .thenReturn(Optional.of(reputation));

                // 아직 만료되지 않은 평판
                when(reputation.getExpiresAt())
                                .thenReturn(LocalDateTime.now().plusDays(1));

                when(reputation.getBlacklisted()).thenReturn(false);
                when(reputation.getWhitelisted()).thenReturn(true);

                assertEquals(
                                DomainReputationService.ReputationStatus.WHITELISTED,
                                service.checkDomain("active.example"));
        }

}
