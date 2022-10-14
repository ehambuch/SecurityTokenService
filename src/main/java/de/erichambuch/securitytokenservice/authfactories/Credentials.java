package de.erichambuch.securitytokenservice.authfactories;

public class Credentials {

	private final String userName;
	
	public Credentials(String user) {
		this.userName = user;
	}

	public String getUser() {
		return userName;
	}
}
