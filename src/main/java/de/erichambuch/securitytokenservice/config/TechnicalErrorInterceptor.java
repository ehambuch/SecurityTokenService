package de.erichambuch.securitytokenservice.config;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.xml.namespace.QName;
import javax.xml.soap.Detail;
import javax.xml.soap.DetailEntry;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;

import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.endpoint.interceptor.EndpointInterceptorAdapter;
import org.springframework.ws.soap.saaj.SaajSoapMessage;

/**
 * Interceptor to polish all technical (runtime) errors.
 * <p>So we return a SOAP Fault according to BiPRO standards without providing internal details (stacktraces etc.).</p>
 */
public class TechnicalErrorInterceptor extends EndpointInterceptorAdapter {

	private static final String NAMESPACE_NACHR = "http://www.bipro.net/namespace/nachrichten";
	
	@Override
	public boolean handleFault(MessageContext messageContext, Object endpoint) throws Exception { 
	    SaajSoapMessage soapResponse = (SaajSoapMessage) messageContext.getResponse();
	    SOAPMessage soapMessage = soapResponse.getSaajMessage();
	    SOAPBody body = soapMessage.getSOAPBody();
	    SOAPFault fault = body.getFault();
	    fault.setFaultString("Technical error");
	    Detail detail = fault.getDetail();
	    if (detail == null) {
		    detail = fault.addDetail();
	        detail.addNamespaceDeclaration("nachr", NAMESPACE_NACHR);
	        DetailEntry entry = detail.addDetailEntry(new QName(NAMESPACE_NACHR, "BiproException"));
	        entry.addChildElement(new QName(NAMESPACE_NACHR, "BiPROVersion")).setValue("2.8.0.1.0");
	        SOAPElement status = entry.addChildElement(new QName(NAMESPACE_NACHR, "Status"));
	        status.addChildElement(new QName(NAMESPACE_NACHR, "StatusID")).setValue("NOK");
	        status.addChildElement(new QName(NAMESPACE_NACHR, "Zeitstempel")).setValue(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
	        SOAPElement meldung = status.addChildElement(new QName(NAMESPACE_NACHR, "Meldung"));
	        meldung.addChildElement(new QName(NAMESPACE_NACHR, "ArtID")).setValue("Fehler");
	        meldung.addChildElement(new QName(NAMESPACE_NACHR, "MeldungID")).setValue("99999");
	        meldung.addChildElement(new QName(NAMESPACE_NACHR, "Text")).setValue("Technical error");
		    return true;
	    } else 
	    	return false;
	}

}
