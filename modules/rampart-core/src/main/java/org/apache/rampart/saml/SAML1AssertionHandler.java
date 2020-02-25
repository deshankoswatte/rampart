/*
 * Copyright (c) The Apache Software Foundation.
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

package org.apache.rampart.saml;

import org.apache.axiom.om.OMElement;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.util.SAMLUtils;
import org.apache.rampart.TokenCallbackHandler;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.SAMLKeyInfo;
//import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.opensaml.saml.saml1.core.Assertion;
import org.opensaml.saml.saml1.core.AttributeStatement;
import org.opensaml.saml.saml1.core.AuthenticationStatement;
import org.opensaml.saml.saml1.core.AuthorizationDecisionStatement;
import org.opensaml.saml.saml1.core.Conditions;
import org.opensaml.saml.saml1.core.Statement;
import org.opensaml.saml.saml1.core.Subject;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import java.util.Iterator;

import static org.apache.ws.security.saml.SAMLUtil.getCredentialFromKeyInfo;

/**
 * This class handles SAML1 assertions.Processes SAML1 assertion and will extract SAML1 attributes
 * such as assertion id, start date, end date etc ...
 */
public class SAML1AssertionHandler extends SAMLAssertionHandler{

    private Assertion assertion;

    public SAML1AssertionHandler(Assertion saml1Assertion) {
        this.assertion = saml1Assertion;
        this.processSAMLAssertion();
    }

    @Override
    public boolean isBearerAssertion() {
        return RahasConstants.SAML11_SUBJECT_CONFIRMATION_BEARER.equals(
                            SAMLUtils.getSAML11SubjectConfirmationMethod(assertion));
    }

    @Override
    protected void processSAMLAssertion() {

        this.setAssertionId(assertion.getID());

        //Read the validity period from the 'Conditions' element, else read it from SC Data
        if (assertion.getConditions() != null) {
            Conditions conditions = assertion.getConditions();
            if (conditions.getNotBefore() != null) {
                this.setDateNotBefore(conditions.getNotBefore().toDate());
            }
            if (conditions.getNotOnOrAfter() != null) {
                this.setDateNotOnOrAfter(conditions.getNotOnOrAfter().toDate());
            }
        }
    }

    @Override
    public byte[] getAssertionKeyInfoSecret(Crypto signatureCrypto, TokenCallbackHandler tokenCallbackHandler)
            throws WSSecurityException {

        RequestData requestData = new RequestData();
        requestData.setCallbackHandler(tokenCallbackHandler);
        requestData.setSigCrypto(signatureCrypto);

        WSDocInfo docInfo = new WSDocInfo(assertion.getDOM().getOwnerDocument()); // TODO Improve ..

        // TODO change this to use SAMLAssertion parameter once wss4j conversion is done ....
        SAMLKeyInfo samlKi = getCredentialFromSubject(assertion,
                requestData, docInfo, true);
        return samlKi.getSecret();
    }


    @Override
    public OMElement getAssertionElement() throws TrustException {
        return (OMElement)this.assertion.getDOM();
    }

    public static SAMLKeyInfo getCredentialFromSubject(Assertion assertion, RequestData data, WSDocInfo docInfo, boolean bspCompliant) throws WSSecurityException {
        byte[] key = getSecretKeyFromCallbackHandler(assertion.getID(), data.getCallbackHandler());
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        } else {
            Iterator i$ = assertion.getStatements().iterator();

            Element keyInfoElement;
            do {
                if (!i$.hasNext()) {
                    return null;
                }

                Statement stmt = (Statement)i$.next();
                Subject samlSubject = null;
                if (stmt instanceof AttributeStatement) {
                    AttributeStatement attrStmt = (AttributeStatement)stmt;
                    samlSubject = attrStmt.getSubject();
                } else if (stmt instanceof AuthenticationStatement) {
                    AuthenticationStatement authStmt = (AuthenticationStatement)stmt;
                    samlSubject = authStmt.getSubject();
                } else {
                    AuthorizationDecisionStatement authzStmt = (AuthorizationDecisionStatement)stmt;
                    samlSubject = authzStmt.getSubject();
                }

                if (samlSubject == null) {
                    throw new WSSecurityException(0, "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
                }

                Element sub = samlSubject.getSubjectConfirmation().getDOM();
                keyInfoElement = WSSecurityUtil.getDirectChildElement(sub, "KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            } while(keyInfoElement == null);

            return getCredentialFromKeyInfo(keyInfoElement, data, docInfo, bspCompliant);
        }
    }

    private static byte[] getSecretKeyFromCallbackHandler(String id, CallbackHandler cb) throws WSSecurityException {
        if (cb != null) {
            WSPasswordCallback pwcb = new WSPasswordCallback(id, 9);

            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception var4) {
                throw new WSSecurityException(0, "noKey", new Object[]{id}, var4);
            }

            return pwcb.getKey();
        } else {
            return null;
        }
    }

}
