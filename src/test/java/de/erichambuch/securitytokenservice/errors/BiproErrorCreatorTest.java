package de.erichambuch.securitytokenservice.errors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.erichambuch.securitytokenservice.config.STSConfiguration;
import de.erichambuch.securitytokenservice.errors.BiproErrorCreator;
import net.bipro.namespace.nachrichten.BiproException;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SpringExtension.class)
class BiproErrorCreatorTest {

	@MockBean
	private STSConfiguration configurationMock;
	
	@InjectMocks
	private BiproErrorCreator errorCreator = new BiproErrorCreator();
	
	@Test
	public void testCreateError() {
		Mockito.when(configurationMock.getExpectedBiproVersion()).thenReturn("2.9.0.1.0");
		BiproException ex = errorCreator.createBiproExceptionForMeldungID("99999", "Testfehler");
		assertNotNull(ex);
		assertEquals("2.9.0.1.0", ex.getBiPROVersion());
		assertNotNull(ex.getStatus());
		assertNotNull(ex.getStatus().getZeitstempel());
		assertEquals("NOK", ex.getStatus().getStatusID().value());
		assertEquals(1, ex.getStatus().getMeldung().size());
		assertEquals("99999", ex.getStatus().getMeldung().get(0).getMeldungID());
		assertEquals("Testfehler", ex.getStatus().getMeldung().get(0).getText());
	}
	
}
