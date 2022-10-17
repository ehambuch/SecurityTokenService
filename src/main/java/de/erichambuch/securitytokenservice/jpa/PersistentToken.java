package de.erichambuch.securitytokenservice.jpa;

import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Persistent entity to store tokens into a database.
 */
@Entity
@Table(name = "TOKENS")
public class PersistentToken {

	@Id
	@Column(name="ID", nullable = false, length=36)
	private String uuid;
	
	@Column(name="TOKEN", nullable = false, length = 512)
	private String jwt;
	
	@Column(name="USERID", nullable = false, length = 30)
	private String userId;
	
	@Column(name="ISSUEDAT", nullable = false)
	private Timestamp issuedAt;
	
	@Column(name="EXPIRESAT", nullable = false)
	private Timestamp expiresAt;

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public Timestamp getIssuedAt() {
		return issuedAt;
	}

	public void setIssuedAt(Timestamp issuedAt) {
		this.issuedAt = issuedAt;
	}

	public Timestamp getExpiresAt() {
		return expiresAt;
	}

	public void setExpiresAt(Timestamp expiresAt) {
		this.expiresAt = expiresAt;
	}
	
	
}
