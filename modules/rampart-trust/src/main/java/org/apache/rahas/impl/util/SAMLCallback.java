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

/**
 * All SAML data retrieving call backs will implement this interface
 * 
 */
public interface SAMLCallback {
    
    /**
     * Attribute callback
     */
    int ATTR_CALLBACK = 1;
    
    /**
     * Subject name identifier
     */
    int NAME_IDENTIFIER_CALLBACK = 2;
    
    /**
     * Returns the type of callback
     * @return
     */
    int getCallbackType();

}
