package org.xmlsoap.schemas.ws._2005._02.trust;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Manually created.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RequestSecurityTokenResponse", propOrder = {
    "requestedSecurityToken",
    "lifetime",
    "tokenType",
    "status",
    "requestedTokenCancelled",
    "biproVersion"
})
@XmlRootElement(name = "RequestSecurityTokenResponse", namespace="http://schemas.xmlsoap.org/ws/2005/02/trust")
public class RequestSecurityTokenResponse {

    @XmlElement(name = "RequestedSecurityToken", required = true)
    protected RequestSecurityTokenType requestedSecurityToken;
    @XmlElement(name = "Lifetime", required = true)
    protected LifetimeType lifetime;
    @XmlElement(name = "TokenType", required=false)
    protected String tokenType;
    @XmlElement(name = "Status", required=false)
    protected Status status;
    @XmlElement(name = "RequestedTokenCancelled", required=false)
    protected RequestedTokenCancelledType requestedTokenCancelled;
    @XmlElement(name = "BiPROVersion", required = false, namespace = "http://www.bipro.net/namespace/nachrichten")
    protected String biproVersion;
   
    public String getBiproVersion() {
		return biproVersion;
	}

	public void setBiproVersion(String biproVersion) {
		this.biproVersion = biproVersion;
	}

	/**
     * Ruft den Wert der requestedSecurityToken-Eigenschaft ab.
     * 
     * @return
     *     possible object is
     *     {@link RequestSecurityTokenType }
     *     
     */
    public RequestSecurityTokenType getRequestedSecurityToken() {
        return requestedSecurityToken;
    }

    /**
     * Legt den Wert der requestedSecurityToken-Eigenschaft fest.
     * 
     * @param value
     *     allowed object is
     *     {@link RequestSecurityTokenType }
     *     
     */
    public void setRequestedSecurityToken(RequestSecurityTokenType value) {
        this.requestedSecurityToken = value;
    }

    /**
     * Ruft den Wert der lifetime-Eigenschaft ab.
     * 
     * @return
     *     possible object is
     *     {@link LifetimeType }
     *     
     */
    public LifetimeType getLifetime() {
        return lifetime;
    }

    /**
     * Legt den Wert der lifetime-Eigenschaft fest.
     * 
     * @param value
     *     allowed object is
     *     {@link LifetimeType }
     *     
     */
    public void setLifetime(LifetimeType value) {
        this.lifetime = value;
    }

	public String getTokenType() {
		return tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public RequestedTokenCancelledType getRequestedTokenCancelled() {
		return requestedTokenCancelled;
	}

	public void setRequestedTokenCancelled(RequestedTokenCancelledType requestedTokenCancelled) {
		this.requestedTokenCancelled = requestedTokenCancelled;
	}

}
