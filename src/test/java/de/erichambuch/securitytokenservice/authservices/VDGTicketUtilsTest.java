package de.erichambuch.securitytokenservice.authservices;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import de.erichambuch.securitytokenservice.authservices.VDGTicket;
import de.erichambuch.securitytokenservice.authservices.VDGTicketUtils;

class VDGTicketUtilsTest {

	private VDGTicketUtils utils = new VDGTicketUtils();
	
	@Test
	void testReadTicket() throws IOException {
		try(InputStream inStream = VDGTicketUtilsTest.class.getResourceAsStream("vdgticket.xml")) {
			VDGTicket ticket = utils.parseTicket(inStream.readAllBytes());
			assertNotNull(ticket);
			assertEquals(1, ticket.authLevel);
			assertEquals("vdg2099", ticket.keyId);
		}
	}
}
