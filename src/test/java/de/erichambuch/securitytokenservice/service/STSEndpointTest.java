package de.erichambuch.securitytokenservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.xml.bind.JAXB;
import javax.xml.namespace.QName;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.xmlsoap.schemas.ws._2005._02.sc.SecurityContextTokenType;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenResponse;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenType;

import de.erichambuch.securitytokenservice.config.XMLUtils;
import de.erichambuch.securitytokenservice.errors.SoapBiproException;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.jpa.PersistentToken;
import de.erichambuch.securitytokenservice.jpa.TokenRepository;
import de.erichambuch.securitytokenservice.jwt.JWTService;

/**
 * Extensive test of the STS Endpoint. This test also checks all error cases and the desired BiPRO messages.
 * <p>We perform an end-to-end test through all components and services, therefore its more an integration test.</p>
 */
@SpringBootTest
public class STSEndpointTest {

	@Autowired
	private JWTService JWTService;
	
	@Autowired
	private TokenRepository tokenRepository;
	
	@Autowired
	private STSEndpoint endpoint;
	
	/**
	 * Request a token with invalid token type.
	 * @throws Exception
	 */
	@Test
	void testInvalidRequest_invalidTokenType() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("invalidRequest_tokenType.xml");
		});
		checkBiproMeldung("NOK", "00910", ex);
	}
	
	/**
	 * Request a token with invalid request type.
	 * @throws Exception
	 */
	@Test
	void testInvalidRequest_invalidRequestType() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("invalidRequest_requestType.xml");
		});
		checkBiproMeldung("NOK", "00911", ex);
	}

	
	/**
	 * Request a token with WS-Security header.
	 * @throws Exception
	 */
	@Test
	void testInvalidRequest_invalidHeader() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("invalidRequest_securityHeader.xml");
		});
		checkBiproMeldung("NOK", "00905", ex);
	}

	@Test
	void testRequestToken_ok() throws Exception {
		Map<String,String> attributes = new HashMap<>();
		attributes.put("${user}", "john"); // should match LDAP test users from test-schema.ldif
		attributes.put("${password}", "secret1");
		RequestSecurityTokenResponse response =	callWebserviceException("requestToken_ok.xml", attributes);
		assertNotNull(response.getRequestedSecurityToken());
		assertNotNull(response.getLifetime());
		assertEquals("2.8.0.1.0", response.getBiproVersion());
		// extract the token
		SecurityContextTokenType token = (SecurityContextTokenType) XMLUtils.findAnyElementValue(response.getRequestedSecurityToken().getAny(), new QName("http://schemas.xmlsoap.org/ws/2005/02/sc", "SecurityContextToken"));
		String biproToken = (String) XMLUtils.findAnyElementValue(token.getAny(), new QName("http://schemas.xmlsoap.org/ws/2005/02/sc", "Identifier"));
		assertTrue(biproToken.startsWith("bipro:"));
	}
	
	
	@Test
	void testRequestToken_invalidUser_nok() throws Exception {
		final Map<String,String> attributes = new HashMap<>();
		attributes.put("${user}", "doeUnknown"); // should match LDAP test users from test-schema.ldif
		attributes.put("${password}", "secret1");
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("requestToken_ok.xml", attributes);
		});
		checkBiproMeldung("NOK", "00960", ex);
	}
	
	@Test
	void testRequestToken_invalidPassword_nok() throws Exception {
		final Map<String,String> attributes = new HashMap<>();
		attributes.put("${user}", "john"); // should match LDAP test users from test-schema.ldif
		attributes.put("${password}", "invalidsecret1");
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("requestToken_ok.xml", attributes);
		});
		checkBiproMeldung("NOK", "00960", ex);
	}
	
	@Test
	void testRequestToken_invalidRequest_nok() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("requestToken_invalid.xml");
		});
		checkBiproMeldung("NOK", "00961", ex);
	}
	
	
	/**
	 * Validate a token - good case.
	 * @throws Exception
	 */
	@Test
	void testValidateToken_ok() throws Exception {
		RequestSecurityTokenResponse response =	callWebserviceException("validateTokenRequest_ok.xml", Collections.singletonMap("${JWT}", JWTService.generateToken("testuser")));
		assertEquals("http://schemas.xmlsoap.org/ws/2005/02/trust/status/valid", response.getStatus().getCode());
	}

	/**
	 * Validate a token - invalid JWT.
	 * @throws Exception
	 */
	@Test
	void testValidateToken_nok() throws Exception {
		RequestSecurityTokenResponse response =	callWebserviceException("validateTokenRequest_ok.xml", Collections.singletonMap("${JWT}", "bipro:INVALIDJWT"));
		assertEquals("http://schemas.xmlsoap.org/ws/2005/02/trust/status/invalid", response.getStatus().getCode());
	}
	
	@Test
	@Transactional
	void testCancelToken_ok() throws Exception {
		// setup
		PersistentToken token = JWTService.generatePersistentToken("testcancel");
		tokenRepository.saveAndFlush(token);
		// and test
		RequestSecurityTokenResponse response =	callWebserviceException("cancelTokenRequest_ok.xml", Collections.singletonMap("${JWT}", token.getJwt()));
		assertNotNull(response.getRequestedTokenCancelled());
		// and check if token is set expired
		Optional<PersistentToken> tokenUpdate = tokenRepository.findById(token.getUuid());
		assertNotNull(tokenUpdate);
		assertNotNull(tokenUpdate.get());
		assert(tokenUpdate.get().getExpiresAt().before(new Timestamp(System.currentTimeMillis()))); // and check if expired
	}
	
	@Test
	void testCancelToken_validTokenNotFound_nok() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("cancelTokenRequest_ok.xml", Collections.singletonMap("${JWT}", JWTService.generateToken("testuser")));
		});
		checkBiproMeldung("NOK", "00919", ex);
	}
	
	private RequestSecurityTokenResponse callWebserviceException(String request) throws Exception {
		InputStream source = STSEndpointTest.class.getResourceAsStream(request);
		assertNotNull(source, request);
		WebServiceMessage message = new WebServiceTemplate().getMessageFactory().createWebServiceMessage(source);
		RequestSecurityTokenType body = JAXB.unmarshal(message.getPayloadSource(), RequestSecurityTokenType.class);
		return endpoint.requestSecurityToken(body, ((SaajSoapMessage)message).getSoapHeader()); 
	}
	
	private RequestSecurityTokenResponse callWebserviceException(String request, Map<String,String> variables) throws Exception {
		InputStream source = STSEndpointTest.class.getResourceAsStream(request);
		assertNotNull(source, request);
		byte[] allbytes = source.readAllBytes();
		String messageTemplate= new String(allbytes, StandardCharsets.UTF_8);
		for(Map.Entry<String, String> entry : variables.entrySet()) {
			if (messageTemplate.contains(entry.getKey()))
				messageTemplate = messageTemplate.replace(entry.getKey(), entry.getValue());
		}
		WebServiceMessage message = new WebServiceTemplate().getMessageFactory().createWebServiceMessage(new ByteArrayInputStream(messageTemplate.getBytes(StandardCharsets.UTF_8)));
		RequestSecurityTokenType body = JAXB.unmarshal(message.getPayloadSource(), RequestSecurityTokenType.class);
		return endpoint.requestSecurityToken(body, ((SaajSoapMessage)message).getSoapHeader()); 
	}
	
	private void checkBiproMeldung(String statusId, String expectedMeldungId, SoapBiproException ex) {
		assertNotNull(ex.getBiproException());
		assertNotNull(ex.getBiproException().getStatus());
		assertEquals(statusId, ex.getBiproException().getStatus().getStatusID().value());
		assertEquals(1, ex.getBiproException().getStatus().getMeldung().size());
		assertEquals(expectedMeldungId, ex.getBiproException().getStatus().getMeldung().get(0).getMeldungID());
	}
}
