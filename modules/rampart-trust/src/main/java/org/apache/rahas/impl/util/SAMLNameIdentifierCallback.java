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

import org.apache.rahas.RahasData;
import org.opensaml.saml.saml1.core.NameIdentifier;

/**
 * This is used retrieve data for the SAMLNameIdentifier.
 * SAMLNameIdentifier can have different formats.
 * Depending on it, NameIdentifier must have different values.
 * It should be implementation specific.
 *
 */
public class SAMLNameIdentifierCallback implements SAMLCallback{
    
    private NameIdentifier nameId = null;
    private String userId = null;
    private RahasData data = null;
    
    public SAMLNameIdentifierCallback(RahasData data){
        this.data = data;
    }
    
    public int getCallbackType(){
        return SAMLCallback.NAME_IDENTIFIER_CALLBACK;
    }

    public NameIdentifier getNameId() {
        return nameId;
    }

    public void setNameId(NameIdentifier nameId) {
        this.nameId = nameId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }

    public RahasData getData() {
        return data;
    }
    
}
