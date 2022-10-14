package org.xmlsoap.schemas.ws._2005._02.trust;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.xmlsoap.schemas.ws._2005._02.sc.SecurityContextTokenType;

/**
 * Manually created.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ValidateToken", propOrder = {
    "securityContextToken"
})
@XmlRootElement(name = "ValidateToken", namespace="http://schemas.xmlsoap.org/ws/2005/02/trust")
public class ValidateToken {
    @XmlElement(name = "SecurityContextToken", required = true)
    protected SecurityContextTokenType securityContextToken;
}
