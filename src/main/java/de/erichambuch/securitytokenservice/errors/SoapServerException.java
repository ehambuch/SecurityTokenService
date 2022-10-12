package de.erichambuch.securitytokenservice.errors;

import org.springframework.ws.soap.server.endpoint.annotation.FaultCode;
import org.springframework.ws.soap.server.endpoint.annotation.SoapFault;

import net.bipro.namespace.nachrichten.BiproException;

/**
 * Exception creating a SOAP-Fault of type Server.
 */
@SoapFault(faultCode = FaultCode.SERVER)
public class SoapServerException extends SoapBiproException {

	private static final long serialVersionUID = -7644358754103139467L;

	public SoapServerException(String message) {
		super(message);
	}

	public SoapServerException(String message, BiproException biproException) {
		super(message, biproException);
	}
	
	public SoapServerException(BiproException biproException) {
		super(biproException.getStatus().getMeldung().get(0).getText(), biproException);
	}
}
