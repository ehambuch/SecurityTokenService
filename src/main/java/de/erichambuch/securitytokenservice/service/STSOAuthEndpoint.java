package de.erichambuch.securitytokenservice.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import de.erichambuch.securitytokenservice.authfactories.Credentials;
import de.erichambuch.securitytokenservice.authfactories.ISecurityHeader;
import de.erichambuch.securitytokenservice.authservices.LdapService;
import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.jwt.JWTService;

/**
 * Simple endpoint for an OAuth2 Client Credential Flow.
 */
@RestController(value = "OAuth2Service")
public class STSOAuthEndpoint {

	@Autowired
	private LdapService ldapService;
	
	@Autowired
	private STSConfiguration configuration;
	
	public static final class TokenResponse {
		String access_token = "";
		String token_type = "Bearer";
		String expires_in = "";

		TokenResponse(String token, int expiresSeconds) {
			this.access_token = token;
			this.expires_in = Integer.toString(expiresSeconds);
		}
	}

	private class OAuthClientSecurityHeader implements ISecurityHeader {
		private final String userName;
		private final transient String password; // TODO besser byte array

		private OAuthClientSecurityHeader(String user, String pwd) {
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
			return "OAuthClient[user=" + userName + "]";
		}
	}

	@Autowired
	private JWTService jwtService;

	@RequestMapping(path = "/ws/oauth/token", method = {RequestMethod.GET, RequestMethod.POST}, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<TokenResponse> token(@RequestParam(name = "grant_type", required = true) String grant_type, 
			@RequestParam(name="client_id", required=true) String client_id,
			@RequestParam(name="client_secret", required=true) String client_secret)

	{
		if ("client_credentials".equals(grant_type) && !isInvalidParam(client_id) && !isInvalidParam(client_secret)) {
			ISecurityHeader security = new OAuthClientSecurityHeader(client_id, client_secret);
			Credentials credentials = security.authenticate();
			if (credentials != null)
				return ResponseEntity.ok().
						cacheControl(CacheControl.noStore()).
						body(
								new TokenResponse(
									jwtService.generateToken(credentials.getUser()), 
									(int)configuration.getTokenLifetime()));
			else
				return ResponseEntity.status(HttpStatus.FORBIDDEN).cacheControl(CacheControl.noStore()).build();
		} else
			return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
	}

	private boolean isInvalidParam(String param) {
		if (param == null)
			return true;
		if (param.trim().length() <= 1)
			return true;
		if (param.length() > 256) // for security reasons we only support up to 256 chars per parameter
			return true;
		return false;
	}
}
