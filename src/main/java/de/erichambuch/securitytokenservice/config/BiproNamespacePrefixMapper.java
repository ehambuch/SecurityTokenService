package de.erichambuch.securitytokenservice.config;

import java.util.HashMap;
import java.util.Map;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * Special class to define fixed namespace prefixes instead of numbered ones (ns1, ns2, ...).
 */
public class BiproNamespacePrefixMapper extends NamespacePrefixMapper {

	private static final Map<String,String> PREFIX_MAP = new HashMap<>();
	
	static {
		PREFIX_MAP.put("http://www.bipro.net/namespace/datentypen", "dt");
		PREFIX_MAP.put("http://www.bipro.net/namespace/nachrichten", "nachr");
		PREFIX_MAP.put("http://schemas.xmlsoap.org/ws/2004/08/addressing", "wsa");
	}
	
	@Override
	public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
		if(requirePrefix) {
			return PREFIX_MAP.getOrDefault(namespaceUri, suggestion);
		} else
			return "";
	}

}
