package de.erichambuch.securitytokenservice.authservices;

import java.time.LocalDateTime;

/**
 * Structure of a VDG ticket.
 */
public class VDGTicket {
	// <Ticket>
	// <TicketInfo>
	String ticketId;
	String targetId;
	public String targetUserId;
	String issuerUserId;
	String userIPAddress;
	int authLevel;
	String authMethod; 
	LocalDateTime authTimestamp; // YYYYmmddHHMMssSSSZ
	String issuerId;
	LocalDateTime issueTimestamp; // YYYYmmddHHMMssSSSZ
	// <Signature>
	byte[] signatureValue; // Signature (base64-decoded)
	String signatureAlgorithm; // e.g. SHA1withRSA
	// <KeyInfo>
	String keyId; // Name of Certificate Public Key in KeyStore (e.g. vdg2018)
	// signed part between <TicketInfo>
	String signedTicketInfo;
}
