package de.erichambuch.securitytokenservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;

import javax.xml.bind.JAXB;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenType;

import de.erichambuch.securitytokenservice.errors.SoapBiproException;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.service.STSEndpoint;

/**
 * Extensive test of the STS Endpoint. This test also checks all error cases and the desired BiPRO messages.
 */
@SpringBootTest
public class STSEndpointTest {

	@Autowired
	private STSEndpoint endpoint;
	
	@Test
	void testInvalidRequest_invalidTokenType() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("invalidRequest_tokenType.xml");
		});
		checkBiproMeldung("NOK", "00910", ex);
	}
	
	@Test
	void testInvalidRequest_invalidRequestType() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("invalidRequest_requestType.xml");
		});
		checkBiproMeldung("NOK", "00911", ex);
	}

	
	@Test
	void testInvalidRequest_invalidHeader() throws Exception {
		SoapClientException ex = assertThrows(SoapClientException.class, ()-> {
			callWebserviceException("invalidRequest_securityHeader.xml");
		});
		checkBiproMeldung("NOK", "00905", ex);
	}


	private void callWebserviceException(String request) throws Exception {
		InputStream source = STSEndpointTest.class.getResourceAsStream(request);
		assertNotNull(source, request);
		WebServiceMessage message = new WebServiceTemplate().getMessageFactory().createWebServiceMessage(source);
		RequestSecurityTokenType body = JAXB.unmarshal(message.getPayloadSource(), RequestSecurityTokenType.class);
		endpoint.requestSecurityToken(body, ((SaajSoapMessage)message).getSoapHeader()); 
	}
	
	private void checkBiproMeldung(String statusId, String expectedMeldungId, SoapBiproException ex) {
		assertNotNull(ex.getBiproException());
		assertNotNull(ex.getBiproException().getStatus());
		assertEquals(statusId, ex.getBiproException().getStatus().getStatusID().value());
		assertEquals(1, ex.getBiproException().getStatus().getMeldung().size());
		assertEquals(expectedMeldungId, ex.getBiproException().getStatus().getMeldung().get(0).getMeldungID());
	}
}
