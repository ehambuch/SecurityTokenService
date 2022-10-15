package de.erichambuch.securitytokenservice.authservices;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Test class for LDAP Services based on the in-memory LDAP component.
 * <p>Please see the application.properties configuration and the test-schema.ldif</p>
 */
@SpringBootTest
public class LdapServiceTest {

	@Autowired
	LdapService ldapService;
	
	@Test
	void testAuthenticateUser_ok() {
		assertEquals("john", ldapService.authenticate("john", "secret1"));
	}
	
	@Test
	void testAuthenticateUser_wrongpassword() {
		assertNull(ldapService.authenticate("john", "secretWrong"));
	}
	
	@Test
	void testAuthenticateUser_wronguser() {
		assertNull(ldapService.authenticate("jonny", "secret"));
	}
	
	@Test
	void testUserExists_ok() {
		assertTrue(ldapService.existsUser("john"));
	}
	
	@Test
	void testUserExists_nok() {
		assertFalse(ldapService.existsUser("johnDoe"));
	}
}
