package de.erichambuch.securitytokenservice.errors;

import net.bipro.namespace.nachrichten.BiproException;

@SuppressWarnings("serial")
public abstract class SoapBiproException extends Exception {
	private final BiproException biproException;
	
	public SoapBiproException(String message) {
		this(message, null);
	}
	
	public SoapBiproException(String message, BiproException e) {
		super(message);
		this.biproException = e;
	}
	
	public BiproException getBiproException() {
		return biproException;
	}

}
