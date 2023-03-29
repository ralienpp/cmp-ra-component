/*
 *  Copyright (c) 2023 Siemens AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.cmpclientcomponent.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.cmpclientcomponent.main.CmpClient;
import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

public class TestSignatureBasedKur extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_Root.pem";

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRa(ConfigurationFactory.buildSignatureBasedDownstreamConfiguration());
    }

    /**
     * Updating a Valid Certificate
     *
     * @throws Exception
     */
    @Test
    public void testKur() throws Exception {
        final CmpClient crClient =
                getSignatureBasedCmpClient(getClientContext(PKIBody.TYPE_CERT_REQ), UPSTREAM_TRUST_PATH);
        final EnrollmentResult crResult = crClient.invokeEnrollment();

        final X509Certificate crEnrolledCertificate = crResult.getEnrolledCertificate();

        final ClientContext kurClientContext = new ClientContext() {

            KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();

            @Override
            public EnrollmentContext getEnrollmentContext() {

                return new EnrollmentContext() {

                    @Override
                    public KeyPair getCertificateKeypair() {
                        return keyPair;
                    }

                    @Override
                    public VerificationContext getEnrollmentTrust() {
                        try {
                            return getEnrollmentCredentials();
                        } catch (final Exception e) {
                            return null;
                        }
                    }

                    @Override
                    public int getEnrollmentType() {
                        return PKIBody.TYPE_KEY_UPDATE_REQ;
                    }

                    @Override
                    public List<TemplateExtension> getExtensions() {
                        return null;
                    }

                    @Override
                    public X509Certificate getOldCert() {
                        return crEnrolledCertificate;
                    }

                    @Override
                    public boolean getRequestImplictConfirm() {
                        // TODO Auto-generated method stub
                        return false;
                    }

                    @Override
                    public String getSubject() {
                        return crEnrolledCertificate.getSubjectX500Principal().getName();
                    }
                };
            }

            @Override
            public String getCertProfile() {
                return "certProfileForKur";
            }

            @Override
            public RevocationContext getRevocationContext() {
                fail("getRevocationContext");
                return null;
            }
        };

        final SignatureValidationCredentials enrollmentCredentials = getEnrollmentCredentials();

        final CmpMessageInterface kurUpstream = new CmpMessageInterface() {

            @Override
            public VerificationContext getInputVerification() {
                return new SignatureValidationCredentials(UPSTREAM_TRUST_PATH, null);
            }

            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }

            @Override
            public CredentialContext getOutputCredentials() {
                // TODO Auto-generated method stub
                return new SignatureCredentialContext() {

                    @Override
                    public List<X509Certificate> getCertificateChain() {
                        final List<X509Certificate> ret = new ArrayList<>(enrollmentCredentials.getAdditionalCerts());
                        ret.add(0, crEnrolledCertificate);
                        return ret;
                    }

                    @Override
                    public PrivateKey getPrivateKey() {
                        return crResult.getPrivateKey();
                    }
                };
            }

            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.reprotect;
            }

            @Override
            public boolean getSuppressRedundantExtraCerts() {
                return false;
            }

            @Override
            public boolean isCacheExtraCerts() {
                return false;
            }

            @Override
            public boolean isMessageTimeDeviationAllowed(final long deviation) {
                return deviation < 10;
            }
        };
        final CmpClient kurClient = new CmpClient(getUpstreamExchange(), kurUpstream, kurClientContext);
        final EnrollmentResult kurResult = kurClient.invokeEnrollment();
        assertNotNull(kurResult);
    }
}
