package de.erichambuch.securitytokenservice.errors;

import org.springframework.ws.soap.server.endpoint.annotation.FaultCode;
import org.springframework.ws.soap.server.endpoint.annotation.SoapFault;

import net.bipro.namespace.nachrichten.BiproException;

/**
 * Exception creating a SOAP-Fault of type Client.
 */
@SoapFault(faultCode = FaultCode.CLIENT)
public class SoapClientException extends SoapBiproException {

	private static final long serialVersionUID = 5786247465979820457L;

	public SoapClientException(String message) {
		super(message, null);
	}

	public SoapClientException(String message, BiproException biproException) {
		super(message, biproException);
	}
	
	public SoapClientException(BiproException biproException) {
		super(biproException.getStatus().getMeldung().get(0).getText(), biproException);
	}
}
