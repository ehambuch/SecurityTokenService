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
@XmlType(name = "RequestSecurityTokenRequest", propOrder = {
    "requestSecurityToken"
})
@XmlRootElement(name = "RequestSecurityTokenRequest", namespace="http://schemas.xmlsoap.org/ws/2005/02/trust")
public class RequestSecurityTokenRequest {

    @XmlElement(name = "RequestSecurityToken", required = true)
    protected RequestSecurityTokenType requestSecurityToken;

    /**
     * Ruft den Wert der requestSecurityToken-Eigenschaft ab.
     * 
     * @return
     *     possible object is
     *     {@link RequestSecurityTokenType }
     *     
     */
    public RequestSecurityTokenType getRequestSecurityToken() {
        return requestSecurityToken;
    }

    /**
     * Legt den Wert der requestSecurityToken-Eigenschaft fest.
     * 
     * @param value
     *     allowed object is
     *     {@link RequestSecurityTokenType }
     *     
     */
    public void setRequestSecurityToken(RequestSecurityTokenType value) {
        this.requestSecurityToken = value;
    }

}
