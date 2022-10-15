package de.erichambuch.securitytokenservice.jwt;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.jpa.PersistentToken;

/**
 * Service that creates JWT (JSON Web Tokens) for a dedicated user.
 */
@Service
public class JWTService {
	
	private final STSConfiguration configuration;
	private final Algorithm algorithm;
	
	@Autowired
	public JWTService(STSConfiguration configuration) {
		this.configuration = configuration;
		this.algorithm = initAlgo();
	}
	
	private Algorithm initAlgo() {
		String algo = configuration.getJwtAlgorithm();
		switch(algo) {
			case "HMAC256":
				return Algorithm.HMAC256(configuration.getJwtSecret());
			case "HMAC512":
				return Algorithm.HMAC512(configuration.getJwtSecret());
				// TODO: more
		}
		throw new ExceptionInInitializerError("Unable to set up algorithm for JWT:"+algo);
	}
	
	/**
	 * Generate a WS-Trust Token with URL <code>bipro:</code> based on a JWT.
	 * @param user the user 
	 * @return the token
	 * @throws IllegalArgumentException
	 * @throws JWTCreationException
	 */
    public String generateToken(String user) throws IllegalArgumentException, JWTCreationException {
    	final LocalDateTime expires = LocalDateTime.now().plusSeconds(configuration.getTokenLifetime());
    	final Date expiresAt = (Date) Date.from(expires.atZone(ZoneId.systemDefault()).toInstant());
        return configuration.getTokenPrefix()+JWT.create()
                .withSubject(user)
                .withJWTId(UUID.randomUUID().toString())
                .withIssuedAt(new java.util.Date(System.currentTimeMillis()))
                .withIssuer(configuration.getJwtIssuer())
                .withExpiresAt(expiresAt)
                .sign(algorithm);
    }

    public PersistentToken generatePersistentToken(String user) throws IllegalArgumentException, JWTCreationException {
    	final LocalDateTime expires = LocalDateTime.now().plusSeconds(configuration.getTokenLifetime());
    	final Date expiresAt = (Date) Date.from(expires.atZone(ZoneId.systemDefault()).toInstant());
    	final PersistentToken token = new PersistentToken();
    	final String uuid = UUID.randomUUID().toString();
    	token.setUuid(uuid);
    	final Timestamp issuedAt = new Timestamp(System.currentTimeMillis());
    	token.setIssuedAt(issuedAt);
    	token.setExpiresAt(new Timestamp(expiresAt.getTime()));
    	token.setUserId(user);
        final String jwtToken = configuration.getTokenPrefix()+JWT.create()
                .withSubject(user)
                .withJWTId(uuid)
                .withIssuedAt(issuedAt)
                .withIssuer(configuration.getJwtIssuer())
                .withExpiresAt(expiresAt)
                .sign(algorithm);
    	token.setJwt(jwtToken);
    	return token;
    }
    
    public String getUUID(String jwt) throws JWTDecodeException {
    	return JWT.decode(removeUriPrefix(jwt)).getId();
    }
    
    public String getUser(String jwt) throws JWTDecodeException {
    	return JWT.decode(removeUriPrefix(jwt)).getSubject();
    }
    
    public String validateTokenAndGetUser(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(algorithm).withIssuer(configuration.getJwtIssuer())
                .build();
        DecodedJWT jwt = verifier.verify(removeUriPrefix(token));
        return jwt.getSubject();
    }
    
    private String removeUriPrefix(String token) {
    	final String uriPrefix = configuration.getTokenPrefix();
    	if (token.startsWith(uriPrefix))
    		return token.substring(uriPrefix.length());
    	else
    		return token;
    }
}