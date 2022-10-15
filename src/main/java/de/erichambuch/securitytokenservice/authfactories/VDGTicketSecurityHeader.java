package de.erichambuch.securitytokenservice.authfactories;

import java.util.Base64;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import de.erichambuch.securitytokenservice.authservices.VDGTicket;
import de.erichambuch.securitytokenservice.authservices.VDGTicketControllerService;
import de.erichambuch.securitytokenservice.errors.BiproErrorCreator;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.errors.SoapServerException;

@Component
public class VDGTicketSecurityHeader implements ISecurityHeaderFactory {

	@Autowired
	private BiproErrorCreator errorCreator;
	
	@Autowired 
	VDGTicketControllerService ticketController;
	
	private class VDGSecurityToken implements ISecurityHeader {
		private final VDGTicket vdgTicket;
		private final String id;
		VDGSecurityToken(VDGTicket ticket, String id) {
			vdgTicket = ticket;
			this.id= id;
		}
		
		public VDGTicket getVDGTicket() {
			return vdgTicket;
		}
		
		public String toString() {
			return "VDGTicketSecurityHeader[]";
		}

		@Override
		public Credentials authenticate() {
			if ( ticketController.validateTicket(vdgTicket)) {
				return new Credentials(vdgTicket.targetUserId);
			} else
				return null;
		}

		@Override
		public String getId() {
			return id;
		}	
	}



	@Override
	public boolean supports(SecurityHeader securityHeader) {
		return (securityHeader.getUsernameToken() == null && securityHeader.getBinaryToken() != null);
	}

	@Override
	public ISecurityHeader createFromSecurityHeader(SecurityHeader securityHeader)
			throws SoapClientException, SoapServerException {
		final BinarySecurityTokenType binaryToken = securityHeader.getBinaryToken();
		if(binaryToken.getEncodingType() == null || !binaryToken.getEncodingType().contains("Base64Binary"))
			throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00961","Invalid EncodingType of VDGTicket"));
		if(binaryToken.getValueType() == null || !"bipro:VDGTicket".equals(binaryToken.getValueType()))
			throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00961","Invalid ValueType of VDGTicket"));
		try {
			final VDGTicket ticket = ticketController.getTicket(Base64.getDecoder().decode(binaryToken.getValue()));
			return new VDGSecurityToken(ticket, binaryToken.getId());
		} catch (IllegalArgumentException e) {
			throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00960","Cannot decrypt VDGTicket"));
		}
	}
}
