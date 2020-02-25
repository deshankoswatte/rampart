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

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.rahas.impl.util.AxiomParserPool;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;

/**
 * Rampart specific SAML bootstrap class. Here we set parser pool to
 * axiom specific one.
 */
public class RampartSAMLBootstrap {

    protected RampartSAMLBootstrap() {
        super();
    }

    public static synchronized void bootstrap() throws InitializationException {

        SAMLInitializer.doBootstrap();
        initializeParserPool();
    }

    protected static void initializeParserPool() throws InitializationException {

        AxiomParserPool pp = new AxiomParserPool();
        pp.setMaxPoolSize(50);
        try {
            pp.initialize();
        } catch (ComponentInitializationException e) {
            throw new InitializationException("Error initializing axiom based parser pool", e);
        }
        XMLObjectProviderRegistrySupport.setParserPool(pp);

    }
}
