package de.erichambuch.securitytokenservice.authservices;

import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
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
	
	private static class UsernameAttributesMapper<MyLdapUser> implements AttributesMapper<Object> {
		static class MyLdapUser {
			String uid;
		}
		@Override
		public Object mapFromAttributes(Attributes attributes) throws NamingException {
			MyLdapUser u = new MyLdapUser();
			u.uid = (String)attributes.get("uid").get();
			return u;
		}	
	}
	
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
	
	public boolean existsUser(String uid) {
		LdapName baseDn;
		try {
			baseDn = new LdapName(configuration.getLdapDn());		
			Filter filter = new EqualsFilter("uid", uid);
			List<Object> users = 
					ldapTemplate.search(baseDn, filter.encode(), 
							new UsernameAttributesMapper<de.erichambuch.securitytokenservice.authservices.LdapService.UsernameAttributesMapper.MyLdapUser>());
			return users.size() > 0;
		} catch (InvalidNameException e) {
			throw new RuntimeException("Invalid configuration for LDAP: "+configuration.getLdapDn());
		}
	}
}
