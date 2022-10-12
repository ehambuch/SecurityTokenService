package de.erichambuch.securitytokenservice.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.bind.PropertyException;

import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.server.endpoint.SoapFaultAnnotationExceptionResolver;
import org.springframework.ws.soap.server.endpoint.SoapFaultDefinition;
import org.springframework.ws.soap.server.endpoint.SoapFaultMappingExceptionResolver;
import org.springframework.ws.soap.server.endpoint.interceptor.PayloadValidatingInterceptor;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.SimpleXsdSchema;
import org.springframework.xml.xsd.XsdSchema;
import org.springframework.xml.xsd.XsdSchemaCollection;
import org.springframework.xml.xsd.commons.CommonsXsdSchemaCollection;

import de.erichambuch.securitytokenservice.errors.SoapBiproException;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.errors.SoapServerException;

/**
 * General Spring configuration for STS.
 */
@EnableWs
@EnableWebSecurity
@Configuration
public class STSConfig extends WsConfigurerAdapter {

	// TODO: Throttling
	
	/**
	 * Configure to use HTTPS in any case, so we have an end-to-end encryption.
	 * Additionally deactivate sessions, CSRF and any authentication.
	 * 
	 * @param security
	 * @return the security filter chain
	 * @throws Exception
	 */
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
		return security.csrf().disable().authorizeRequests(authorize -> authorize.anyRequest().permitAll())
				.requiresChannel(channel -> channel.anyRequest().requiresSecure())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).build();
	}

	/**
	 * Enable XSD Schema validation for incoming messages.
	 * 
	 * @param interceptors
	 */
	@Override
	public void addInterceptors(List<EndpointInterceptor> interceptors) {
		PayloadValidatingInterceptor validatingInterceptor = new PayloadValidatingInterceptor();
		validatingInterceptor.setValidateRequest(true);
		validatingInterceptor.setValidateResponse(false);
		validatingInterceptor.setXsdSchemaCollection(resourceSchemaCollection());
		interceptors.add(validatingInterceptor);
	}

	/**
	 * Enable special formatting of SOAP Faults.
	 * 
	 * @return
	 */
	@Bean
	public SoapFaultAnnotationExceptionResolver soapFaultAnnotationExceptionResolverNew() { 
		SoapFaultAnnotationExceptionResolver exceptionResolver = new DetailSoapFaultDefinitionExceptionResolver();
		exceptionResolver.setOrder(-1); // priority over other Resolver in WsConfigurationSupport
		return exceptionResolver;
	}
	
	@Bean
	public ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(
			ApplicationContext applicationContext) {
		MessageDispatcherServlet servlet = new MessageDispatcherServlet();
		servlet.setApplicationContext(applicationContext);
		return new ServletRegistrationBean<>(servlet, "/ws/*");
	}

	@Bean
	public DefaultWsdl11Definition defaultWsdl11Definition() {
		DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
		wsdl11Definition.setPortTypeName("SecurityTokenServiceType");
		wsdl11Definition.setTargetNamespace("http://www.bipro.net/namespace");
		wsdl11Definition.setSchemaCollection(resourceSchemaCollection());
		return wsdl11Definition;
	}

	@Bean
	public XsdSchemaCollection resourceSchemaCollection() {
		CommonsXsdSchemaCollection collection = new CommonsXsdSchemaCollection();
		collection.setXsds(new ClassPathResource("WEB-INF/xsd/ws-trust.xsd")); // imports all other
		return collection;
	}

	/**
	 * We have to make all the W3C and BiPRO packages known to Spring.
	 * 
	 * @return the custom marshaller
	 * @throws PropertyException
	 */
	@Bean
	public Jaxb2Marshaller jaxb2Marshaller() {
		Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
		Map<String, Object> jaxbContextProperties = new HashMap<>();
		// TODO anders lösne
		// jaxbContextProperties.put("com.sun.xml.internal.bind.namespacePrefixMapper",
		// new BiproNamespacePrefixMapper());
		marshaller.setJaxbContextProperties(jaxbContextProperties);
		marshaller.setPackagesToScan(new String[] { "net.bipro.namespace", "net.bipro.namespace.datentypen",
				"net.bipro.namespace.nachrichten",
				"org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0",
				"org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0",
				"org.xmlsoap.schemas.ws._2004._08.addressing", "org.xmlsoap.schemas.ws._2005._02.sc",
				"org.xmlsoap.schemas.ws._2004._09.policy", "org.xmlsoap.schemas.ws._2005._02.trust" });
		return marshaller;
	}
}