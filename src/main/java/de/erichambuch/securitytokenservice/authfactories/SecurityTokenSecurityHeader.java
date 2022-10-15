package de.erichambuch.securitytokenservice.authfactories;

import javax.xml.bind.JAXBElement;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.sun.istack.logging.Logger;

import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.errors.BiproErrorCreator;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.jwt.JWTService;

/**
 * Authenticate against own token in Security Header.
 */
@Component
public class SecurityTokenSecurityHeader implements ISecurityHeaderFactory {

	private static final Logger LOGGER = Logger.getLogger(SecurityTokenSecurityHeader.class); 
	@Autowired
	JWTService jwtService;
	
	@Autowired
	BiproErrorCreator errorCreator;
	
	@Autowired
	STSConfiguration configuration;
	
	public final class STSToken implements ISecurityHeader {

		private final String token;
		private final String id;
		
		private STSToken(String jwt, String id) {
			this.token = jwt;
			this.id = id;
		}
		
		public String getId() {
			return id;
		}
		
		@Override
		public Credentials authenticate() {
			try {
				return new Credentials(jwtService.validateTokenAndGetUser(token));
				// TODO: check if token is valid in database
			} catch(JWTVerificationException e) {
				LOGGER.warning("Error verifying JWT token", e);
				return null;
			}
		}
		
		public String getToken() {
			return token;
		}
		
	}
	
	@Override
	public boolean supports(SecurityHeader securityHeader) {
		return ( securityHeader.getSecurityContextToken() != null);
	}

	@Override
	public ISecurityHeader createFromSecurityHeader(SecurityHeader securityHeader) throws SoapClientException {
		for(Object element : securityHeader.getSecurityContextToken().getAny()) {
			if (element instanceof JAXBElement) {
				@SuppressWarnings("rawtypes")
				final JAXBElement el = (JAXBElement)element;
				if ("Identifier".equals(el.getName().getLocalPart())) {
					final String token = (String)el.getValue();
					if(token == null)
						throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00909","Empty identifier"));
					final String id = securityHeader.getSecurityContextToken().getId();
					return new STSToken(token, id);
				}
			}
		}
		throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00909","Missing identifier"));
	}

}
