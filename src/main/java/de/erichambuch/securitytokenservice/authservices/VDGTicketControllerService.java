package de.erichambuch.securitytokenservice.authservices;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import de.erichambuch.securitytokenservice.config.STSConfiguration;

@Service
public class VDGTicketControllerService {
	
	/**
	 * Private key of Pfefferminiza to decrypt ticket.
	 */
	private PrivateKey privateKey;

	/**
	 * Keystore with Public Key Certificates of VDG. Each certificate has an alias for the key id.
	 */
	private KeyStore vdgKeystore;
	
	private STSConfiguration configuration;
	private VDGTicketUtils utils;
	
	@Autowired
	public VDGTicketControllerService(STSConfiguration configuration, VDGTicketUtils utils) {
		this.configuration = configuration;
		this.utils = utils;
		init();
	}
	
	/**
	 * Initialize key stores. Only executed if parameters are set.
	 */
	private void init() { 
		if(configuration.getVdgKeyStorePath() != null && configuration.getVdgKeyStorePath().length()>0) {
			try {
				vdgKeystore = utils.loadKeyStore(configuration.getVdgKeyStorePath(), configuration.getVdgKeyStorePassword());
				final KeyStore privateKeystore = utils.loadKeyStore(configuration.getPrivateKeyStorePath(), configuration.getPrivateKeyStorePassword());
				privateKey = (PrivateKey) privateKeystore.getKey(configuration.getPrivateKeyAlias(), configuration.getPrivateKeyPassword());
				if(privateKey == null)
					throw new IllegalArgumentException("No private key found for alias: "+configuration.getPrivateKeyAlias());
			} catch(Exception e) {
	 			throw new ExceptionInInitializerError(e);
	 		}
		}
	}
	
	public VDGTicket getTicket(byte vdgTicketEncrypted[]) throws IllegalArgumentException {
		try {
			// Step 1: Decrypt ticket with private key of Pfefferminzia
			byte[] ticketData = utils.decipher(vdgTicketEncrypted, privateKey);
			// Step 2: Parse VDGTicket as XML
			VDGTicket vdgTicket = utils.parseTicket(ticketData);
			// Step 3: Check Signature of XML
			Certificate cert = vdgKeystore.getCertificate(vdgTicket.keyId);
			utils.checkSignature(vdgTicket.signedTicketInfo.getBytes(StandardCharsets.UTF_8), 
					vdgTicket.signatureValue,
					vdgTicket.signatureAlgorithm, 
					cert.getPublicKey());
			// Step 4: return Ticket (still unchecked)
			return vdgTicket;
		} catch(GeneralSecurityException | NullPointerException e) {
			throw new IllegalArgumentException("Invalid VDG ticket", e);
		}
	}

	public boolean validateTicket(VDGTicket ticket) {
		return true; // TODO
	}
}
