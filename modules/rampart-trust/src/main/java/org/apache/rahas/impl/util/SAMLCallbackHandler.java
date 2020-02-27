/*
 * Copyright The Apache Software Foundation.
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

package org.apache.rahas.impl.util;

import org.opensaml.saml.common.SAMLException;

/**
 * SAMLCallback Handler enables you to add data to the
 * to the SAMLAssertion.
 * 
 * For example Assertions, NameIdentifiers.
 * 
 */
public interface SAMLCallbackHandler {

    /**
     * SAMLCallback object has indicates what kind of data is required.
     * if(callback.getCallbackType() == SAMLCallback.ATTR_CALLBACK)
     * {
     *     SAMLAttributeCallback attrCallback = (SAMLAttributeCallback)callback;
     *     \//Retrieve required data from the RahasData inside SAMLAttributeCallback 
     *     \//Add your SAMLAttributes to the attrCallback here.
     *     
     * }
     * @param callback
     * @throws SAMLException
     */
    void handle(SAMLCallback callback) throws SAMLException;

}
