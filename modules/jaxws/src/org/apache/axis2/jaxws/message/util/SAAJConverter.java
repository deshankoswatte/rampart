/*
 * Copyright 2004,2005 The Apache Software Foundation.
 * Copyright 2006 International Business Machines Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.axis2.jaxws.message.util;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.jaxws.message.MessageException;


/**
 * SAAJConverter
 * Provides Conversion between SAAJ and OM
 * Constructed via the SAAJConverterFactory
 */
public interface SAAJConverter {
	/**
	 * Convert OM SOAPEnvleope to SAAJ SOAPEnvelope
	 * @param omElement
	 * @return SOAPEnvelope
	 * @throws MessageException
	 */
	public SOAPEnvelope toSAAJ(org.apache.axiom.soap.SOAPEnvelope omElement)
		throws MessageException;

	/**
	 * Convert SAAJ SOAPEnvelope to OM SOAPEnvelope
	 * @param saajEnvelope
	 * @return OM Envelope
	 * @throws MessageException
	 */
	public org.apache.axiom.soap.SOAPEnvelope toOM(SOAPEnvelope saajEnvelope)
		throws MessageException;
	
	/**
	 * Convert SOAPElement into an OMElement
	 * @param soapElement
	 * @return OMElement
	 * @throws MessageException
	 */
	public OMElement toOM(SOAPElement soapElement) 
		throws MessageException;
	
	/**
	 * Convert omElement into a SOAPElement and add it to the parent SOAPElement
	 * @param omElement
	 * @param parent SOAPElement
	 * @return SOAPElement that was added to the parent.
	 * @throws MessageException
	 */
	public SOAPElement toSAAJ(OMElement omElement, SOAPElement parent)
		throws MessageException;
}