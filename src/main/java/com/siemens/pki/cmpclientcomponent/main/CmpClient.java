/*
 *  Copyright (c) 2022 Siemens AG
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
package com.siemens.pki.cmpclientcomponent.main;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CrlUpdateRetrievalHandler;
import com.siemens.pki.cmpracomponent.configuration.GetCaCertificatesHandler;
import com.siemens.pki.cmpracomponent.configuration.GetCertificateRequestTemplateHandler;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * a CMP client implementation
 *
 */
public class CmpClient
        implements CrlUpdateRetrievalHandler,
                GetCaCertificatesHandler,
                GetCertificateRequestTemplateHandler,
                GetRootCaCertificateUpdateHandler {
    /**
     * result of an enrollment transaction
     *
     */
    public interface EnrollmentResult {
        /**
         * get enrolled certificate
         *
         * @return the enrolled certificate
         */
        X509Certificate getEnrolledCertificate();

        /**
         * get certificate chain (1st intermediate certificate up to root
         * certificate) of the enrolled certificate
         *
         * @return the certificate chain of the enrolled certificate
         */
        List<X509Certificate> getEnrollmentChain();

        /**
         * get private key related to the enrolled certificate
         *
         * @return the private key related to the enrolled certificate
         */
        PrivateKey getPrivateKey();
    }

    private final UpstreamExchange upstreamExchange;

    private final CmpMessageInterface upstreamConfiguration;

    private final ClientContext clientContext;

    /**
     * @param upstreamExchange
     *            the {@link UpstreamExchange} interface implemented by the
     *            wrapping application.
     *
     * @param upstreamConfiguration
     *            configuration for the upstream CMP interface towards the CA
     *
     * @param clientContext
     *            client specific configuration
     */
    public CmpClient(
            final UpstreamExchange upstreamExchange,
            final CmpMessageInterface upstreamConfiguration,
            final ClientContext clientContext) {
        this.upstreamExchange = upstreamExchange;
        this.upstreamConfiguration = upstreamConfiguration;
        this.clientContext = clientContext;
    }

    /**
     * invoke a Get CA certificates GENM request
     * {@inheritDoc}
     */
    @Override
    public List<X509Certificate> getCaCertificates() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * invoke a Get certificate request template GENM request
     * {@inheritDoc}
     */
    @Override
    public byte[] getCertificateRequestTemplate() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * invoke an CRL Update Retrieval GENM request
     * {@inheritDoc}
     */
    @Override
    public List<X509CRL> getCrls(final String dpn, final String[] issuer, final Date thisUpdate) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * invoke a Get root CA certificate update GENM request
     * {@inheritDoc}
     */
    @Override
    public RootCaCertificateUpdateResponse getRootCaCertificateUpdate(final X509Certificate oldRootCaCertificate) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * invoke a enrollment transaction
     *
     * @return result of successful enrollment transaction or <code>null</code>
     */
    public EnrollmentResult invokeEnrollment() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * invoke a revocation transaction
     *
     * @return <code>true</code> on success, <code>false</code> on failure
     */
    public boolean invokeRevocation() {
        // TODO Auto-generated method stub
        return false;
    }
}
