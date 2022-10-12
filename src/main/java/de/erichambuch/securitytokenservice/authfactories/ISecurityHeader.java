package de.erichambuch.securitytokenservice.authfactories;

public interface ISecurityHeader {
	
	/**
	 * Authenticate the user from the given information.
	 * @return the credentials if successful, null otherwise
	 */
	public Credentials authenticate();
}
