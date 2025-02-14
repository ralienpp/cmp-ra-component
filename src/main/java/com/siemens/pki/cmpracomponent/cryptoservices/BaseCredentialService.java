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
package com.siemens.pki.cmpracomponent.cryptoservices;

import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * base class for certificate based signing and encryption services
 */
public class BaseCredentialService {

    private final SignatureCredentialContext config;

    public BaseCredentialService(final SignatureCredentialContext config) {
        this.config = config;
    }

    public X509Certificate getEndCertificate() {
        return config.getCertificateChain().get(0);
    }

    public PrivateKey getPrivateKey() {
        return config.getPrivateKey();
    }

    protected List<X509Certificate> getCertChain() {
        return config.getCertificateChain();
    }

    protected AlgorithmIdentifier getSignatureAlgorithm() {
        return AlgorithmHelper.getSigningAlgIdFromName(getSignatureAlgorithmName());
    }

    protected String getSignatureAlgorithmName() {
        return config.getSignatureAlgorithmName();
    }
}
