package de.erichambuch.securitytokenservice.authservices;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import org.springframework.stereotype.Service;

import de.erichambuch.securitytokenservice.config.XMLUtils;

/**
 * Utility class for handling VDG Tickets.
 */
@Service
public class VDGTicketUtils {

	public KeyStore loadKeyStore(String url, char password[]) throws IOException, GeneralSecurityException {
		try(InputStream stream = new URL(url).openStream()) {
			KeyStore keyStore = KeyStore.getInstance("jks");
			keyStore.load(stream, password);
			return keyStore;
		}
	}
	
	public byte[] decipher(byte[] input, PrivateKey privateKey) throws GeneralSecurityException {
		String algo = privateKey.getAlgorithm();
		if ("RSA".equals(algo))
			algo = "RSA/ECB/PKCS1Padding";
		final Cipher cipher = Cipher.getInstance(algo);
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);    
	    final int length = input.length;
		// Block size must be determined by length of RSA Modulus if not given
	    int blockSize = cipher.getBlockSize();
	    if (blockSize == 0)
	    	blockSize = ((RSAPrivateKey)privateKey).getModulus().bitLength() >> 3;
	    int inputOffset = 0;
	    ByteBuffer outBuffer = ByteBuffer.allocate(cipher.getOutputSize(input.length));
		while(inputOffset < length) {
			int inputLen = (inputOffset+blockSize) > length ? (length-inputOffset) : blockSize; // min(blockSize,remaining len)
			outBuffer.put(cipher.doFinal(input, inputOffset, inputLen));
			inputOffset += inputLen;
		}
		return Arrays.copyOfRange(outBuffer.array(), 0, outBuffer.position());
	}
	
	public boolean checkSignature(byte[] input, byte[] sign, String algorithm, PublicKey publicKey) throws GeneralSecurityException {
		if (algorithm == null)
			algorithm = "SHA1withRSA";
		Signature signature = Signature.getInstance(algorithm);
		signature.initVerify(publicKey);
		signature.update(input);
		return signature.verify(sign);
	}
	
	public VDGTicket parseTicket(byte[] inputStream) {
		String xml = new String(inputStream, StandardCharsets.UTF_8);
		VDGTicket ticket = new VDGTicket();
		ticket.signedTicketInfo = XMLUtils.getContent(xml, "TicketInfo");
		ticket.ticketId = XMLUtils.getContent(xml, "TicketId");
		ticket.targetId = XMLUtils.getContent(xml, "TargetId");
		ticket.targetUserId = XMLUtils.getContent(xml, "TargetUserId");
		ticket.authLevel = Integer.parseInt(XMLUtils.getContent(xml, "AuthLevel"));
		ticket.issuerId = XMLUtils.getContent(xml, "IssuerId");
		ticket.issueTimestamp = LocalDateTime.parse(XMLUtils.getContent(xml, "IssueTimestamp"), DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS'Z'"));
		ticket.keyId = XMLUtils.getContent(xml, "KeyId");
		ticket.signatureValue = Base64.getDecoder().decode(XMLUtils.getContent(xml, "SignatureValue"));
		ticket.signatureAlgorithm = XMLUtils.getContent(xml, "SignatureAlgorithm");
		return ticket;
	}
	
	public boolean validateTicketSignature(VDGTicket ticket, PublicKey publicKey) throws GeneralSecurityException {
		return checkSignature(ticket.signedTicketInfo.getBytes(StandardCharsets.UTF_8), ticket.signatureValue, ticket.signatureAlgorithm, publicKey);
	}
	
}
