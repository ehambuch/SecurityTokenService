package de.erichambuch.securitytokenservice.authservices;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.stereotype.Service;

import de.erichambuch.securitytokenservice.config.STSConfiguration;

@Service
public class LdapService {

	@Autowired
	private LdapTemplate ldapTemplate;
	
	@Autowired 
	private STSConfiguration configuration;
	
	public String authenticate(String uid, String password) {
		LdapName baseDn;
		try {
			baseDn = new LdapName(configuration.getLdapDn());		
			Filter filter = new EqualsFilter("uid", uid);
			if(ldapTemplate.authenticate(baseDn, filter.encode(), password))
				return uid;
			else
				return null;
		} catch (InvalidNameException e) {
			throw new RuntimeException("Invalid configuration for LDAP: "+configuration.getLdapDn());
		}
	}
}
