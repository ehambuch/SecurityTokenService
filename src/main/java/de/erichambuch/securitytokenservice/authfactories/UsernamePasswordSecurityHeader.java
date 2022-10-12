package de.erichambuch.securitytokenservice.authfactories;

import javax.xml.bind.JAXBElement;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.PasswordString;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import de.erichambuch.securitytokenservice.authservices.LdapService;
import de.erichambuch.securitytokenservice.errors.BiproErrorCreator;
import de.erichambuch.securitytokenservice.errors.SoapClientException;

@Component
public class UsernamePasswordSecurityHeader implements ISecurityHeaderFactory {

	private static final String QNAME_PASSWORD = "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Password";
	private static final String TYPE_PASSWORDTEXT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
	
	@Autowired
	private BiproErrorCreator errorCreator;
	
	@Autowired
	protected LdapService ldapService;
	
	private class UPWSecurityHeader implements ISecurityHeader {
		
		private final String userName;
		private final transient String password; // TODO besser byte arra
		  
		private UPWSecurityHeader(String user, String pwd) {
			this.userName = user;
			this.password = pwd;
		}
		
		@Override
		public Credentials authenticate() {
			String userAuthenticated;
			if((userAuthenticated = ldapService.authenticate(userName, password)) != null)
				return new Credentials(userAuthenticated);
			else
				return null;
		}

		
		public String toString() {
			return "UsernamePassword[user="+userName+"]";
		}
	}

	@Autowired
	public UsernamePasswordSecurityHeader() {
		
	}

	@Override
	public boolean supports(SecurityHeader securityHeader) {
		return ( securityHeader.getUsernameToken() != null && securityHeader.getBinaryToken() == null);
	}

	@Override
	public ISecurityHeader createFromSecurityHeader(SecurityHeader securityHeader) throws SoapClientException {
		final UsernameTokenType token = securityHeader.getUsernameToken();
		final String userName = token.getUsername().getValue();
		String password = null;
		for (Object obj : token.getAny()) {
			if (obj instanceof JAXBElement) {
				@SuppressWarnings("rawtypes")
				final JAXBElement element = (JAXBElement) obj;
				final String elementName = element.getName().toString();
				if (QNAME_PASSWORD.equals(elementName)) {
					final PasswordString pwString = (PasswordString) element.getValue();
					if (!TYPE_PASSWORDTEXT.equals(pwString.getType()))
						throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00961","Invalid Type of Password"));
					password = pwString.getValue();
				} 
			}
		}
		if ( password == null || "".equals(password) )
			throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00961","Invalid password"));
		return new UPWSecurityHeader(userName, password);
	}
	
}
