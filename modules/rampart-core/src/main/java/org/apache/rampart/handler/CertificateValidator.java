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

package org.apache.rampart.handler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.validate.SignatureTrustValidator;

import java.security.cert.X509Certificate;

/**
 * Validates the certificate in a signature.
 */
public class CertificateValidator extends SignatureTrustValidator {

    /**
     * Checks the validity of the given certificate. For more info see SignatureTrustValidator.verifyTrustInCert.
     * @param certificate Certificate to be validated.
     * @param signatureCrypto Signature crypto instance.
     * @param data Request data.
     * @throws WSSecurityException If an error occurred while trying to access Crypto and Certificate properties.
     */
    void validateCertificate(X509Certificate certificate, Crypto signatureCrypto, RequestData data) throws WSSecurityException {
        verifyTrustInCerts(new X509Certificate[]{certificate}, signatureCrypto, data, false);
    }

}
