
package com.dongmulbw.backend.service;

import com.dongmulbw.backend.repository.DomainReputationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=none"
})
class DomainReputationIntegrationTest {

    @Autowired
    private DomainReputationRepository repository;

    @Autowired
    private DomainReputationService service;

    @Test
    void checkDatabaseConnection() {
        assertNotNull(repository);
        assertNotNull(service);

        long count = repository.count();

        System.out.println(
                "domain_reputation 데이터 개수: " + count);

        assertTrue(count >= 0);
    }

    @Test
    void unknownDomainReturnsUnknown() {
        // DB에 등록되지 않은 도메인을 조회
        String domain = "nonexistent-test-domain.invalid";

        assertFalse(repository.findByDomain(domain).isPresent());

        assertEquals(
                DomainReputationService.ReputationStatus.UNKNOWN,
                service.checkDomain(domain));
    }
}
