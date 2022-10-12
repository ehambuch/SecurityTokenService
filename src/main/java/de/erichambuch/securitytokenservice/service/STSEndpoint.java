package de.erichambuch.securitytokenservice.service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.AttributedDateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import org.springframework.ws.soap.SoapHeaderElement;
import org.springframework.ws.soap.server.endpoint.annotation.SoapAction;
import org.springframework.ws.soap.server.endpoint.annotation.SoapHeader;
import org.xmlsoap.schemas.ws._2005._02.sc.SecurityContextTokenType;
import org.xmlsoap.schemas.ws._2005._02.trust.LifetimeType;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenResponse;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenType;
import org.xmlsoap.schemas.ws._2005._02.trust.Status;

import de.erichambuch.securitytokenservice.authfactories.Credentials;
import de.erichambuch.securitytokenservice.authfactories.ISecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.SecurityTokenSecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.SpringAuthenticatedSecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.UsernamePasswordSecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.VDGTicketSecurityHeader;
import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.errors.BiproErrorCreator;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.errors.SoapServerException;
import de.erichambuch.securitytokenservice.jwt.JWTService;

@Endpoint(value = "SecurityTokenService")
@RequestMapping(path = {"/ws/sts/UserPasswordLogin", "/ws/sts/VDGTicketLogin", "/ws/sts/SpringAuthentication", "/ws/sts/ValidateToken"})
public class STSEndpoint {

	protected static final String NAMESPACE_URI = "http://schemas.xmlsoap.org/ws/2005/02/trust";

	private static final String QNAME_TOKEN_TYPE = "{http://schemas.xmlsoap.org/ws/2005/02/trust}TokenType";
	private static final String QNAME_REQUEST_TYPE = "{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestType";
	private static final String QNAME_BIPRO_VERSION = "{http://www.bipro.net/namespace/nachrichten}BiPROVersion";
	protected static final String QNAME_SECURIY = "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security";

	private static final String TOKEN_TYPE_SCT = "http://schemas.xmlsoap.org/ws/2005/02/sc/sct";

	private static final String REQUEST_ISSUE = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
	private static final String REQUEST_VALIDATE = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
	private static final String REQUEST_CANCEL = "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel";

	@Autowired
	private JWTService jwtService;

	@Autowired
	protected STSConfiguration configuration;

	@Autowired
	protected ApplicationContext context;

	@Autowired
	protected BiproErrorCreator errorCreator;

	// Factories for different methods
	@Autowired
	private UsernamePasswordSecurityHeader userpasswordFactory;
	@Autowired
	private VDGTicketSecurityHeader vdgFactory;
	@Autowired
	private SpringAuthenticatedSecurityHeader springFactory;
	@Autowired
	private SecurityTokenSecurityHeader securityTokenFactory;
	
	@Autowired
	public STSEndpoint() {
	}

	@PayloadRoot(namespace = NAMESPACE_URI, localPart = "RequestSecurityToken")
	@ResponsePayload
	@SoapAction("urn:RequestSecurityToken")
	@SoapAction("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue")
	@SoapAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
	@SoapAction("http://docs.oasis-open.org/ws-sx/ws-trust/2005/02/trust/RST/Validate")
	public RequestSecurityTokenResponse requestSecurityToken(@RequestPayload RequestSecurityTokenType request,
			@SoapHeader(value = QNAME_SECURIY) org.springframework.ws.soap.SoapHeader soapHeader)
			throws SoapClientException, SoapServerException {
		String tokenType = "";
		String requestType = "";
		String biproVersion = "undefined";
		for (Object obj : request.getAny()) {
			if (obj instanceof JAXBElement) {
				@SuppressWarnings("rawtypes")
				final JAXBElement element = (JAXBElement) obj;
				final String elementName = element.getName().toString();
				if (QNAME_TOKEN_TYPE.equals(elementName)) {
					tokenType = (String) element.getValue();
				} else if (QNAME_REQUEST_TYPE.equals(elementName)) {
					requestType = (String) element.getValue();
				} else if (QNAME_BIPRO_VERSION.equals(elementName)) {
					biproVersion = (String) element.getValue();
				} // else: ignore
			}
		}

		// Check Request
		final ISecurityHeader securityHeader = validateRequest(tokenType, requestType, biproVersion, soapHeader);

		// Authentication Service
		Credentials credentials = securityHeader.authenticate();

		if (credentials != null) {
			if (REQUEST_ISSUE.equals(requestType)) {
				RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
				response.setRequestedSecurityToken(createSecurityToken(credentials));
				response.setLifetime(createLifetime());
				if (!"undefined".equals(biproVersion))
					response.setBiproVersion(biproVersion);
				return response;
			} else if (REQUEST_VALIDATE.equals(requestType)) {
				return createValidationResponse(true);
			} else
				throw new SoapClientException(
						errorCreator.createBiproExceptionForMeldungID("00911", "Given RequestType is not supported")); 
		} else {
			if (REQUEST_VALIDATE.equals(requestType))
				return createValidationResponse(false);
			else // Error
				throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00960", "User not authenticated"));
		}
	}
	
	private RequestSecurityTokenResponse createValidationResponse(boolean valid) {
		RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
		Status status = new Status();
		status.setCode(valid ? "http://schemas.xmlsoap.org/ws/2005/02/trust/status/valid" : "http://schemas.xmlsoap.org/ws/2005/02/trust/status/invalid");
		response.setStatus(status);
		return response;
	}
	
	/**
	 * Validate the input request
	 * 
	 * @param tokenType
	 * @param requestType
	 * @param biproVersion
	 * @param soapHeader
	 * @throws SoapClientException
	 */
	private ISecurityHeader validateRequest(String tokenType, String requestType, String biproVersion,
			org.springframework.ws.soap.SoapHeader soapHeader) throws SoapClientException, SoapServerException {
		if (!TOKEN_TYPE_SCT.equals(tokenType)) {
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00910", "TokenType is not (correctly) set"));
		}
		if (!(REQUEST_ISSUE.equals(requestType) || REQUEST_VALIDATE.equals(requestType) )) {
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00911", "Given RequestType is not supported"));
		}
		// nur wenn konfiguriert, prüfen wir die BiPRO Version
		if (configuration.getExpectedBiproVersion() != null && !"".equals(configuration.getExpectedBiproVersion())) {
			if (!configuration.getExpectedBiproVersion().equals(biproVersion))
				throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00931",
						"BiPROVersion is not as expected: " + configuration.getExpectedBiproVersion()));
		}
		if (soapHeader != null) {
			for(Iterator<SoapHeaderElement> it = soapHeader.examineHeaderElements(QName.valueOf(QNAME_SECURIY)); it.hasNext(); ) { 
				return analyseSecurityHeader(it.next());
			}
		}
		throw new SoapClientException(
				errorCreator.createBiproExceptionForMeldungID("00905", "SOAP-Security Header missing"));
	}

	/**
	 * Creates SecurityToken block.
	 * 
	 * @param credentials the credentials of the user
	 * @return the SecurityToken
	 */
	private RequestSecurityTokenType createSecurityToken(Credentials credentials) {
		String biproToken = configuration.getTokenPrefix() + jwtService.generateToken(credentials.getUser()); // generate an URI
		RequestSecurityTokenType type = new RequestSecurityTokenType();
		SecurityContextTokenType token = new SecurityContextTokenType();
		JAXBElement<SecurityContextTokenType> jaxbToken = new org.xmlsoap.schemas.ws._2005._02.sc.ObjectFactory()
				.createSecurityContextToken(token);
		JAXBElement<String> jaxbIdentifier = new org.xmlsoap.schemas.ws._2005._02.sc.ObjectFactory()
				.createIdentifier(biproToken);
		token.getAny().add(jaxbIdentifier);
		type.getAny().add(jaxbToken);
		return type;
	}

	/**
	 * Creates Lifetime block.
	 * 
	 * @return the Lifetime of the token
	 */
	private LifetimeType createLifetime() {
		LifetimeType type = new LifetimeType();
		AttributedDateTime created = new AttributedDateTime();
		created.setValue(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
		AttributedDateTime expires = new AttributedDateTime();
		expires.setValue(LocalDateTime.now().plusSeconds(configuration.getTokenLifetime())
				.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
		type.setCreated(created);
		type.setExpires(expires);
		return type;
	}

	protected ISecurityHeader analyseSecurityHeader(org.springframework.ws.soap.SoapHeaderElement securityHeader)
			throws SoapClientException, SoapServerException {
		try {
			final JAXBContext jaxbContext = JAXBContext.newInstance(SecurityHeader.class);
			final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			final JAXBElement<SecurityHeader> security = (JAXBElement<SecurityHeader>) unmarshaller
					.unmarshal(securityHeader.getSource(), SecurityHeader.class);
			if (userpasswordFactory.supports(security.getValue())) {
				ISecurityHeader supportedHeader = userpasswordFactory.createFromSecurityHeader(security.getValue());
				if (supportedHeader == null)
					throw new SoapServerException(
							errorCreator.createBiproExceptionForMeldungID("00907", "Invalid Security Header"));
				else
					return supportedHeader;
			} else if (vdgFactory.supports(security.getValue())) {
				ISecurityHeader supportedHeader = vdgFactory.createFromSecurityHeader(security.getValue());
				if (supportedHeader == null)
					throw new SoapServerException(
							errorCreator.createBiproExceptionForMeldungID("00907", "Invalid Security Header"));
				else
					return supportedHeader;
			} else if( springFactory.supports(security.getValue())) {
				ISecurityHeader supportedHeader = springFactory.createFromSecurityHeader(security.getValue());
				if (supportedHeader == null)
					throw new SoapServerException(
							errorCreator.createBiproExceptionForMeldungID("00907", "Invalid Security Header"));
				else
					return supportedHeader;
			} else if (securityTokenFactory.supports(security.getValue())) {
				ISecurityHeader supportedHeader = securityTokenFactory.createFromSecurityHeader(security.getValue());
				if (supportedHeader == null)
					throw new SoapServerException(
							errorCreator.createBiproExceptionForMeldungID("00907", "Invalid Security Header"));
				else
					return supportedHeader;
			}

			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00906", "Invalid Security in SOAP-Header"));
		} catch (JAXBException e) {
			throw new SoapServerException(
					errorCreator.createBiproExceptionForMeldungID("00901", "Error analyzing Security in SOAP-Header"));
		}
	}
	
}
