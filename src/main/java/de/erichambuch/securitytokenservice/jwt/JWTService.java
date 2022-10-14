package de.erichambuch.securitytokenservice.jwt;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import de.erichambuch.securitytokenservice.config.STSConfiguration;

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
	
    public String generateToken(String user) throws IllegalArgumentException, JWTCreationException {
    	final LocalDateTime expires = LocalDateTime.now().plusSeconds(configuration.getTokenLifetime());
    	final Date expiresAt = (Date) Date.from(expires.atZone(ZoneId.systemDefault()).toInstant());
        return JWT.create()
                .withSubject(user)
                .withJWTId(UUID.randomUUID().toString())
                .withIssuedAt(new java.util.Date(System.currentTimeMillis()))
                .withIssuer(configuration.getJwtIssuer())
                .withExpiresAt(expiresAt)
                .sign(algorithm);
    }

    public String validateTokenAndGetUser(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(algorithm).withIssuer(configuration.getJwtIssuer())
                .build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getSubject();
    }
}