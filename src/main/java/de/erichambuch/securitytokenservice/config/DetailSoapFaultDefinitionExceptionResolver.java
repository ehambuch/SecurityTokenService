package de.erichambuch.securitytokenservice.config;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Result;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ws.soap.SoapFault;
import org.springframework.ws.soap.SoapFaultDetail;
import org.springframework.ws.soap.server.endpoint.SoapFaultAnnotationExceptionResolver;

import de.erichambuch.securitytokenservice.errors.SoapBiproException;
import net.bipro.namespace.nachrichten.BiproException;

public class DetailSoapFaultDefinitionExceptionResolver extends SoapFaultAnnotationExceptionResolver  {

	private static final Log LOG = LogFactory.getLog(DetailSoapFaultDefinitionExceptionResolver.class);
	
    @Override
    protected void customizeFault(Object endpoint, Exception ex, SoapFault fault) {
    	LOG.warn("Exception processed ", ex);
        if (ex instanceof SoapBiproException) {
            BiproException serviceEx = ((SoapBiproException) ex).getBiproException();
            SoapFaultDetail detail = fault.addFaultDetail();
            detail.addNamespaceDeclaration("bipro", "http://www.bipro.net/namespace");
            detail.addNamespaceDeclaration("nachr", "http://www.bipro.net/namespace/nachrichten");
            Result result = detail.getResult(); // Marshall into the SOAP Fault Result
            try {
            	JAXBContext.newInstance(BiproException.class).createMarshaller().marshal(serviceEx, result);
            } catch(JAXBException e) {
            	LOG.error("Error marshalling BiproException", e);
            }
        } 
    }
}
