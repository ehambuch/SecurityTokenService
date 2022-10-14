package de.erichambuch.securitytokenservice.authfactories;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;

import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.errors.SoapServerException;

public interface ISecurityHeaderFactory {
	
	/**
	 * Checks if this factory supports the given soap:Security header.
	 * @param securityHeader
	 * @return true if supported
	 */
	public boolean supports(SecurityHeader securityHeader);
	
	/**
	 * Retrieve security header information from SOAP request.
	 * @param securityHeader the SOAP header
	 * @return the security information
	 * @throws SoapClientException
	 * @throws SoapServerException
	 */
	public ISecurityHeader createFromSecurityHeader(SecurityHeader securityHeader) throws SoapClientException, SoapServerException;
}
