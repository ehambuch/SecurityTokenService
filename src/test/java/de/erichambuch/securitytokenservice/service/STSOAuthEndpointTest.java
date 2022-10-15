package de.erichambuch.securitytokenservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import de.erichambuch.securitytokenservice.authservices.LdapService;
import de.erichambuch.securitytokenservice.service.STSOAuthEndpoint.TokenResponse;

/**
 * Extensive test of the STS OAuth. This test also checks all error cases.
 */
@SpringBootTest
public class STSOAuthEndpointTest {

	@MockBean
	private LdapService ldapService;
	
	@Autowired
	private STSOAuthEndpoint endpoint;
	
	@Test
	void testInvalidRequest_invalidGrantType() throws Exception {
		assertEquals(HttpStatus.BAD_REQUEST, endpoint.token("unknown", "1", "1").getStatusCode());
	}
	
	@Test
	void testInvalidRequest_invalidClientId() throws Exception {
		assertEquals(HttpStatus.BAD_REQUEST, endpoint.token("client_credentials", "", "").getStatusCode());
	}
	
	@Test
	void testInvalidRequest_invalidPassword() throws Exception {
		Mockito.when(ldapService.authenticate("user1", "pwwrong")).thenReturn(null);
		assertEquals(HttpStatus.FORBIDDEN, endpoint.token("client_credentials", "user1", "pwwrong").getStatusCode());
	}
	
	@Test
	void testInvalidRequest_ok() throws Exception {
		Mockito.when(ldapService.authenticate("user2", "pwd")).thenReturn("user2");
		ResponseEntity<TokenResponse> response = endpoint.token("client_credentials", "user2", "pwd");
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("Bearer", response.getBody().token_type);
		assertNotNull(response.getBody().expires_in);
		assertNotNull(response.getBody().access_token);
		assertTrue(response.getHeaders().get("Cache-Control").contains("no-store"));
	}
}
