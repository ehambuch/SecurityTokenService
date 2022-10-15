package de.erichambuch.securitytokenservice.authfactories;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

/**
 * Implementation of (empty) SecurityHeader that relies on other authentication (e.g. BASIC or some reverse proxy).
 */
@Component
public class SpringAuthenticatedSecurityHeader implements ISecurityHeaderFactory, ISecurityHeader {

	@Override
	public Credentials authenticate() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if(auth != null && auth.isAuthenticated()) {
			return new Credentials(((User)auth.getPrincipal()).getUsername());
		}
		return null;
	}

	@Override
	public boolean supports(SecurityHeader securityHeader) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if(auth == null)
			return false;
		return (auth.getPrincipal() instanceof User);
	}

	@Override
	public ISecurityHeader createFromSecurityHeader(SecurityHeader securityHeader) {
		return new SpringAuthenticatedSecurityHeader();
	}

	@Override
	public String getId() {
		return null;
	}
}
