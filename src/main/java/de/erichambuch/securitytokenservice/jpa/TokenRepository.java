package de.erichambuch.securitytokenservice.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * JPA access layer for tokens.
 */
@Repository
public interface TokenRepository extends JpaRepository<PersistentToken, String> {
}
