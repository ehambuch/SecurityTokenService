package de.erichambuch.securitytokenservice.config;

import java.io.InputStream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class STSConfiguration {

	
	/**
	 * If define, then BiPROVersion will be checked. Otherwise will be ignored in request.
	 */
	@Value("${sts.expectedBiPROVersion}")
	private String expectedBiproVersion;
	
	@Value("${sts.tokenPrefix}")
	private String tokenPrefix;
	
	@Value("${sts.jwt.issuer}") 
	private String jwtIssuer = "SecurityTokenService";
	
	@Value("${sts.jwt.algorithm}")
	private String jwtAlgorithm = "HMAC256";
	
	@Value("${sts.jwt.secret}")
	private String jwtSecret;
	
	@Value("${sts.ldap.dn}")
	private String ldapDn;
	
	@Value("${sts.vdg.keystore.url}")
	private String vdgKeystorePath;
	
	@Value("{$sts.vdg.keystore.password}")
	private String vdgKeystorePassword;
	
	@Value("${sts.company.keystore.url}")
	private String privateKeystorePath;
	
	@Value("${sts.company.keystore.password}")
	private String privateKeystorePassword;
	
	@Value("${sts.company.privatekey.alias}")
	private String privateKeyAlias;

	@Value("${sts.company.privatekey.password}")
	private String privateKeyPassword;
	
	/**
	 * Validity of a token in seconds.
	 */
	@Value("${sts.token_lifetime}")
	private int tokenLifetime = 30*60;

	
	public String getExpectedBiproVersion() {
		return returnValueEmptyOrNotNull(expectedBiproVersion);
	}
	
	public String getTokenPrefix() {
		return tokenPrefix != null ? tokenPrefix : "";
	}
	
	public String getJwtIssuer() {
		return jwtIssuer;
	}

	public String getJwtAlgorithm() {
		return jwtAlgorithm;
	}

	public String getJwtSecret() {
		return jwtSecret;
	}

	public int getTokenLifetime() {
		return tokenLifetime;
	}
	
	private String returnValueEmptyOrNotNull(String value) {
		if ( value == null || "".equals(value) || value.trim().length() == 0)
			return null;
		else
			return value;
	}

	public String getLdapDn() {
		return ldapDn;
	}

	public String getVdgKeyStorePath() {
		return vdgKeystorePath;
	}

	public char[] getVdgKeyStorePassword() {
		return vdgKeystorePassword != null ? vdgKeystorePassword.toCharArray() : null;
	}

	public String getPrivateKeyStorePath() {
		return privateKeystorePath;
	}
	
	public String getPrivateKeyAlias() {
		return privateKeyAlias;
	}

	public char[] getPrivateKeyPassword() {
		return privateKeyPassword != null ? privateKeyPassword.toCharArray() : null;
	}

	public char[] getPrivateKeyStorePassword() {
		return privateKeystorePassword != null ? privateKeystorePassword.toCharArray() : null;
	}


}
