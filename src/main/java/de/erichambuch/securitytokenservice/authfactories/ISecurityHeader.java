package de.erichambuch.securitytokenservice.authfactories;

public interface ISecurityHeader {
	
	/**
	 * Authenticate the user from the given information.
	 * @return the credentials if successful, null otherwise
	 */
	public Credentials authenticate();
	
	/**
	 * Returns Id of SOAP-Security Header if given
	 * @return the if for reference or null
	 */
	public String getId();
}
