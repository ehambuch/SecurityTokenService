package de.erichambuch.securitytokenservice.errors;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;

import de.erichambuch.securitytokenservice.config.STSConfiguration;
import net.bipro.namespace.datentypen.STMeldungsart;
import net.bipro.namespace.datentypen.STStatus;
import net.bipro.namespace.nachrichten.BiproException;
import net.bipro.namespace.nachrichten.CTMeldung;
import net.bipro.namespace.nachrichten.CTStatus;

/**
 * Created a SOAP Fault detailed message with a BiPROException according to BiPRO Norm 250.
 */
@Service
public class BiproErrorCreator {

	@Autowired
	private STSConfiguration configuration;
	
	public BiproException createBiproExceptionForMeldungID(String meldungId, String message) {
		BiproException ex = new BiproException();
		ex.setBiPROVersion(getBiproVersion());
		CTStatus status = new CTStatus();
		ex.setStatus(status);
		//status.setProzessID(RequestContextHolder.currentRequestAttributes().getSessionId()); // TODO: RequestID generieren am Anfang fuer Loggin
		status.setSchwebe(false);
		status.setZeitstempel(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
		status.setStatusID(STStatus.NOK);
		CTMeldung meldung = new CTMeldung();
		status.getMeldung().add(meldung);
		meldung.setArtID(STMeldungsart.FEHLER);
		meldung.setText(message);
		meldung.setMeldungID(meldungId);
		return ex;
	}
	
	private String getBiproVersion() {
		return configuration.getExpectedBiproVersion() != null ? configuration.getExpectedBiproVersion() : "2.8.0.1.0";
	}
}
