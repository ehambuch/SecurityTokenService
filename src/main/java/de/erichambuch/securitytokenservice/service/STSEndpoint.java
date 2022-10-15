package de.erichambuch.securitytokenservice.service;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.Optional;

import javax.persistence.PersistenceException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityHeader;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.AttributedDateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import org.springframework.ws.soap.SoapHeaderElement;
import org.springframework.ws.soap.server.endpoint.annotation.SoapAction;
import org.springframework.ws.soap.server.endpoint.annotation.SoapHeader;
import org.xmlsoap.schemas.ws._2005._02.sc.SecurityContextTokenType;
import org.xmlsoap.schemas.ws._2005._02.trust.CancelTargetType;
import org.xmlsoap.schemas.ws._2005._02.trust.LifetimeType;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenResponse;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestSecurityTokenType;
import org.xmlsoap.schemas.ws._2005._02.trust.RequestedTokenCancelledType;
import org.xmlsoap.schemas.ws._2005._02.trust.Status;

import com.auth0.jwt.exceptions.JWTDecodeException;

import de.erichambuch.securitytokenservice.authfactories.Credentials;
import de.erichambuch.securitytokenservice.authfactories.ISecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.SecurityTokenSecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.SecurityTokenSecurityHeader.STSToken;
import de.erichambuch.securitytokenservice.authfactories.SpringAuthenticatedSecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.UsernamePasswordSecurityHeader;
import de.erichambuch.securitytokenservice.authfactories.VDGTicketSecurityHeader;
import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.config.XMLUtils;
import de.erichambuch.securitytokenservice.errors.BiproErrorCreator;
import de.erichambuch.securitytokenservice.errors.SoapBiproException;
import de.erichambuch.securitytokenservice.errors.SoapClientException;
import de.erichambuch.securitytokenservice.errors.SoapServerException;
import de.erichambuch.securitytokenservice.jpa.PersistentToken;
import de.erichambuch.securitytokenservice.jpa.TokenRepository;
import de.erichambuch.securitytokenservice.jwt.JWTService;

@Endpoint(value = "SecurityTokenService")
@RequestMapping(path = { "/ws/sts/UserPasswordLogin", "/ws/sts/VDGTicketLogin", "/ws/sts/SpringAuthentication",
		"/ws/sts/ValidateToken", "/ws/sts/CancelToken"  })
public class STSEndpoint {

	protected static final String NAMESPACE_WS_TRUST_URI = "http://schemas.xmlsoap.org/ws/2005/02/trust";

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

	@Autowired
	protected TokenRepository tokenRepository;

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

	/**
	 * Main operation.
	 * <p>
	 * Implemented operations are <code>Issue</code> and <code>Validate</code>.
	 * <p>
	 * Spring WS Framework obviously does not support different methods for
	 * different operations, so I packed all operations into one method.
	 * </p>
	 * 
	 * @param request    the SOAP Request
	 * @param soapHeader SOAP Header with WS-Security
	 * @return the SOAP Response
	 * @throws SoapClientException on Client fault
	 * @throws SoapServerException on Server fault
	 */
	@PayloadRoot(namespace = NAMESPACE_WS_TRUST_URI, localPart = "RequestSecurityToken")
	@ResponsePayload
	@SoapAction("urn:RequestSecurityToken")
	@SoapAction("http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue")
	@SoapAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")
	@SoapAction("http://docs.oasis-open.org/ws-sx/ws-trust/2005/02/trust/RST/Validate")
	@SoapAction("http://docs.oasis-open.org/ws-sx/ws-trust/2005/02/trust/RST/Cancel")
	@Transactional(timeout = 30)
	public RequestSecurityTokenResponse requestSecurityToken(@RequestPayload RequestSecurityTokenType request,
			@SoapHeader(value = QNAME_SECURIY) org.springframework.ws.soap.SoapHeader soapHeader)
			throws SoapBiproException {
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
					if (tokenType != null)
						tokenType = tokenType.trim();
				} else if (QNAME_REQUEST_TYPE.equals(elementName)) {
					requestType = (String) element.getValue();
					if (requestType != null)
						requestType = requestType.trim();
				} else if (QNAME_BIPRO_VERSION.equals(elementName)) {
					biproVersion = (String) element.getValue();
					if (biproVersion != null)
						biproVersion = biproVersion.trim();
				} // else: ignore
			}
		}

		// Check Request
		final ISecurityHeader securityHeader = validateRequest(tokenType, requestType, biproVersion, soapHeader);

		// Authentication Service
		Credentials credentials = securityHeader.authenticate();

		if (credentials != null) {
			if (REQUEST_ISSUE.equals(requestType)) { // Operation: Issue
				return createIssueResponse(request, securityHeader, credentials);
				
			} else if (REQUEST_VALIDATE.equals(requestType)) { // Operation: Validate
				return createValidationResponse(true);
			} else if (REQUEST_CANCEL.equals(requestType)) { // Operation: Cancel
				return cancelToken(request, securityHeader, credentials);
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

	private RequestSecurityTokenResponse createIssueResponse(RequestSecurityTokenType request,
			ISecurityHeader securityHeader, Credentials credentials) {
		RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
		PersistentToken token = jwtService.generatePersistentToken(credentials.getUser());
		response.setRequestedSecurityToken(createSecurityToken(credentials, token.getJwt()));
		response.setLifetime(createLifetime());
		if (configuration.isPersistTokens()) {
			tokenRepository.saveAndFlush(token);
		}
		response.setBiproVersion(configuration.getResponseBiproVersion());
		return response;
	}

	/**
	 * Perform the <code>Cancel</code> operation. We assume that the request has
	 * already been validated.
	 * 
	 * @param request        the SOAP body
	 * @param securityHeader the SOAP header
	 * @param credentials    the credentials of authenticated user
	 * @return the response on success
	 * @throws SoapBiproException in case of faults
	 */
	private RequestSecurityTokenResponse cancelToken(RequestSecurityTokenType request, ISecurityHeader securityHeader,
			Credentials credentials) throws SoapBiproException {
		final CancelTargetType cancelTarget = XMLUtils.findAnyElement(request.getAny(),
				new QName(NAMESPACE_WS_TRUST_URI, "CancelTarget"), CancelTargetType.class);
		if (cancelTarget == null)
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00912", "CancelTarget missing"));
		final SecurityTokenReferenceType reference = XMLUtils.getElement(cancelTarget.getAny(), SecurityTokenReferenceType.class);
		if (reference == null)
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00913", "SecurityTokenReference missing"));
		final ReferenceType refType = XMLUtils.findAnyElement(reference.getAny(),
				new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
						"Reference"),
				ReferenceType.class);
		if (refType == null)
			throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00914", "Reference missing"));
		if (refType.getURI() == null)
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00915", "Reference URI missing"));
		if (!refType.getURI().replace("#", "").equals(securityHeader.getId()))
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00915", "Reference URI missing"));
		final String token = ((STSToken) securityHeader).getToken();
		if (credentials.getUser().equalsIgnoreCase(jwtService.getUser(token))) {
			try {
				Optional<PersistentToken> persitentToken = tokenRepository.findById(jwtService.getUUID(token));
				if (persitentToken != null && persitentToken.isPresent()) {
					Timestamp now = new Timestamp(System.currentTimeMillis());
					if (persitentToken.get().getExpiresAt().after(now)) {
						persitentToken.get().setExpiresAt(now);
						tokenRepository.saveAndFlush(persitentToken.get());
					} // else: expired anyway
				} else
					throw new SoapClientException(
							errorCreator.createBiproExceptionForMeldungID("00919", "Token not found"));
				// create Response
				RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
				response.setRequestedTokenCancelled(new RequestedTokenCancelledType());
				response.setBiproVersion(configuration.getResponseBiproVersion());
				return response;
			} catch (JWTDecodeException | PersistenceException e) {
				throw new SoapServerException(errorCreator.createBiproExceptionForMeldungID("99999", "Internal error"));
			}
		} else
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00916", "SCT does not match authenticated user"));
	}

	/**
	 * Create a response for Validate operation.
	 * 
	 * @param valid true if valid
	 * @return the response
	 */
	private RequestSecurityTokenResponse createValidationResponse(boolean valid) {
		RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
		Status status = new Status();
		status.setCode(valid ? "http://schemas.xmlsoap.org/ws/2005/02/trust/status/valid"
				: "http://schemas.xmlsoap.org/ws/2005/02/trust/status/invalid");
		response.setStatus(status);
		return response;
	}

	/**
	 * Validate the input request.
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
		if (!(REQUEST_ISSUE.equals(requestType) || REQUEST_VALIDATE.equals(requestType)
				|| REQUEST_CANCEL.equals(requestType))) {
			throw new SoapClientException(
					errorCreator.createBiproExceptionForMeldungID("00911", "Given RequestType is not supported"));
		}
		// nur wenn konfiguriert, prüfen wir die BiPRO Version
		if (configuration.getExpectedBiproVersion() != null) {
			if (!configuration.getExpectedBiproVersion().equals(biproVersion))
				throw new SoapClientException(errorCreator.createBiproExceptionForMeldungID("00931",
						"BiPROVersion is not as expected: " + configuration.getExpectedBiproVersion()));
		}
		if (soapHeader != null) {
			for (Iterator<SoapHeaderElement> it = soapHeader.examineHeaderElements(QName.valueOf(QNAME_SECURIY)); it
					.hasNext();) {
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
	private RequestSecurityTokenType createSecurityToken(Credentials credentials, String tokenJWT) {
		RequestSecurityTokenType type = new RequestSecurityTokenType();
		SecurityContextTokenType token = new SecurityContextTokenType();
		JAXBElement<SecurityContextTokenType> jaxbToken = new org.xmlsoap.schemas.ws._2005._02.sc.ObjectFactory()
				.createSecurityContextToken(token);
		JAXBElement<String> jaxbIdentifier = new org.xmlsoap.schemas.ws._2005._02.sc.ObjectFactory()
				.createIdentifier(tokenJWT);
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
			} else if (springFactory.supports(security.getValue())) {
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
