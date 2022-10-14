package de.erichambuch.sts.securitytokenservice.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.auth0.jwt.exceptions.SignatureVerificationException;

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
	public void testCreateJWT_invalidSignature() {
		assertThrowsExactly(SignatureVerificationException.class, () -> {
			jwtService.validateTokenAndGetUser("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		});
	}
}
