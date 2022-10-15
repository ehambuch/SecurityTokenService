package org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.xmlsoap.schemas.ws._2005._02.sc.SecurityContextTokenType;

/**
 * Manually created JAXB for Security SOAP-Header.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(namespace = SecurityHeader.SECURITY_NS, name = "Security")
public class SecurityHeader {

	public static final String SECURITY_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

	@XmlElement(name = "UsernameToken", required = false, namespace = SECURITY_NS)
	protected UsernameTokenType usernameToken;

	@XmlElement(name = "BinarySecurityToken", required = false, namespace = SECURITY_NS)
	protected BinarySecurityTokenType binaryToken;

	@XmlElement(name = "SecurityContextToken", required = false, namespace = "http://schemas.xmlsoap.org/ws/2005/02/sc")
	protected SecurityContextTokenType securityContextToken;
	
	public SecurityContextTokenType getSecurityContextToken() {
		return securityContextToken;
	}

	public void setSecurityContextToken(SecurityContextTokenType securityContextToken) {
		this.securityContextToken = securityContextToken;
	}

	public UsernameTokenType getUsernameToken() {
		return usernameToken;
	}

	public void setUsernameToken(UsernameTokenType usernameToken) {
		this.usernameToken = usernameToken;
	}

	public BinarySecurityTokenType getBinaryToken() {
		return binaryToken;
	}

	public void setBinaryToken(BinarySecurityTokenType binaryToken) {
		this.binaryToken = binaryToken;
	}

}
