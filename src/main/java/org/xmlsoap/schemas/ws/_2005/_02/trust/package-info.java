// Manually created file in order to prive correct namespaces
@javax.xml.bind.annotation.XmlSchema(
		xmlns = {
				@javax.xml.bind.annotation.XmlNs(prefix="nachr", namespaceURI = "http://www.bipro.net/namespace/nachrichten"),
				@javax.xml.bind.annotation.XmlNs(prefix="dt", namespaceURI = "http://www.bipro.net/namespace/datentypen"),
				@javax.xml.bind.annotation.XmlNs(prefix="wsa", namespaceURI = "http://schemas.xmlsoap.org/ws/2004/08/addressing"),
				@javax.xml.bind.annotation.XmlNs(prefix="wsse", namespaceURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"),
					@javax.xml.bind.annotation.XmlNs(prefix="wsp", namespaceURI = "http://schemas.xmlsoap.org/ws/2004/09/policy"),
						@javax.xml.bind.annotation.XmlNs(prefix="wsc", namespaceURI="http://schemas.xmlsoap.org/ws/2005/02/sc")
				}, 
		namespace = "http://schemas.xmlsoap.org/ws/2005/02/trust", elementFormDefault = javax.xml.bind.annotation.XmlNsForm.QUALIFIED)
package org.xmlsoap.schemas.ws._2005._02.trust;
