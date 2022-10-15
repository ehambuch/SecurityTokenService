package de.erichambuch.securitytokenservice.config;

import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

/**
 * Utility class to handle JAXBElements in case of different XML frameworks.
 * 
 * <p>The reason is that many elements are defined as <em>any</em> in the XSD and therefore in the JAXB classes.</p>
 */
public class XMLUtils {

	/**
	 * Get an Element that is defined as Any.
	 * @param jaxbElement the element from getAny()
	 * @param clazz expeced type
	 * @return the element or null
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static <T> T getElement(Object jaxbElement, Class<T> clazz) {
		if(jaxbElement instanceof JAXBElement) {
			final JAXBElement element = (JAXBElement) jaxbElement;
			return (T)element.getValue();
		} else if (jaxbElement != null && jaxbElement.getClass() == clazz) {
			return (T)jaxbElement;
		}
		return null;
	}
	
	/**
	 * Find a dedicated Element in Any list.
	 * 
	 * @param anyElements list from getAny()
	 * @param qname the elements name
	 * @return the element's value or null
	 */
	public static Object findAnyElementValue(List<Object> anyElements, QName qname) {
		for (Object obj : anyElements) {
			if (obj instanceof JAXBElement) {
				@SuppressWarnings("rawtypes")
				final JAXBElement element = (JAXBElement) obj;
				final String elementName = element.getName().toString();
				if (qname.toString().equals(elementName)) {
					return element.getValue();
				} 
			}
		}
		return null;
	}
	
	/**
	 * Find a dedicated Element in Any list.
	 *
	 * @param anyElements list from getAny()
	 * @param qname the elements name
	 * @param clazz the desired type
	 * @return the element or null
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static <T> T findAnyElement(List<Object> anyElements, QName qname, Class<T> clazz) {
		for (Object obj : anyElements) {
			if (obj instanceof JAXBElement) {
				final JAXBElement element = (JAXBElement) obj;
				final String elementName = element.getName().toString();
				if (qname.toString().equals(elementName)) {
					Object el = element.getValue();
					if(el != null && el.getClass() == clazz)
						return (T)el;
					else if (el instanceof JAXBElement) {
						return (T) ((JAXBElement)el).getValue();
					}
				} 
			}
		}
		return null;
	}
}
