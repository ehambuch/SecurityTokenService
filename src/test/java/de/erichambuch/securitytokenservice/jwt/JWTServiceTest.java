package de.erichambuch.securitytokenservice.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.auth0.jwt.exceptions.SignatureVerificationException;

import de.erichambuch.securitytokenservice.jpa.PersistentToken;
import de.erichambuch.securitytokenservice.jwt.JWTService;

@SpringBootTest
class JWTServiceTest {

	@Autowired
	private JWTService jwtService;
	
	@Test
	public void testCreateJWT_ok() {
		String jwtToken = jwtService.generateToken("testuser");
		assertEquals("testuser", jwtService.validateTokenAndGetUser(jwtToken));
	}
	
	@Test
	public void testCreatePersistentJWT_ok() {
		PersistentToken token = jwtService.generatePersistentToken("testuser");
		assertEquals("testuser", token.getUserId());
		assertEquals(jwtService.getUUID(token.getJwt()), token.getUuid());
		long now = System.currentTimeMillis();
		assertTrue(now-token.getIssuedAt().getTime() < 1000); // max 1 second
		assertTrue(token.getExpiresAt().after(token.getIssuedAt()));
		assertEquals("testuser", jwtService.validateTokenAndGetUser(token.getJwt()));
	}
	
	@Test
	public void testCreateJWT_invalidSignature() {
		assertThrowsExactly(SignatureVerificationException.class, () -> {
			jwtService.validateTokenAndGetUser("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		});
	}
}
