/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.rahas;

import org.apache.rahas.impl.util.SAMLAttributeCallback;
import org.apache.rahas.impl.util.SAMLCallback;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.apache.rahas.impl.util.SAMLNameIdentifierCallback;
import org.apache.rahas.impl.util.SAMLUtils;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml1.core.Attribute;
import org.opensaml.saml.saml1.core.NameIdentifier;

public class SAMLDataProvider implements SAMLCallbackHandler{
	
	public void handle(SAMLCallback callback) throws SAMLException {
		
		if(callback.getCallbackType() == SAMLCallback.ATTR_CALLBACK){
			SAMLAttributeCallback cb = (SAMLAttributeCallback)callback;

            try {
                Attribute attribute = SAMLUtils.createAttribute("Name", "https://rahas.apache.org/saml/attrns", "Custom/Rahas");
                cb.addAttributes(attribute);
            } catch (TrustException e) {
                throw new SAMLException("Error creating attribute", e);
            }

		}else if(callback.getCallbackType() == SAMLCallback.NAME_IDENTIFIER_CALLBACK){
			SAMLNameIdentifierCallback cb = (SAMLNameIdentifierCallback)callback;
            try {
                NameIdentifier nameId = SAMLUtils.createNamedIdentifier("David", NameIdentifier.EMAIL);
                cb.setNameId(nameId);
            } catch (TrustException e) {
                throw new SAMLException("Error creating name identifier", e);
            }
		}
		
	}
}
