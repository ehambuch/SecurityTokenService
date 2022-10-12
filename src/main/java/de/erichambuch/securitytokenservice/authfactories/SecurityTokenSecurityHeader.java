package de.erichambuch.securitytokenservice.authfactories;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.jwt.JWTService;

/**
 * Authenticate against own token in Security Header.
 */
@Component
public class SecurityTokenSecurityHeader implements ISecurityHeaderFactory {

	@Autowired
	JWTService jwtService;
	
	@Autowired
	STSConfiguration configuration;
	
	private final class STSToken implements ISecurityHeader {

		private final String token;
		
		private STSToken(String jwt) {
			token = jwt;
		}
		@Override
		public Credentials authenticate() {
			return new Credentials(jwtService.validateTokenAndGetUser(token));
		}
		
	}
	
	@Override
	public boolean supports(SecurityHeader securityHeader) {
		return ( securityHeader.getSecurityContextToken() != null);
	}

	@Override
	public ISecurityHeader createFromSecurityHeader(SecurityHeader securityHeader) throws SoapClientException {
		final String token = securityHeader.getSecurityContextToken().getIdentifier();
		return new STSToken(token.replace(configuration.getTokenPrefix(), ""));
	}

}
