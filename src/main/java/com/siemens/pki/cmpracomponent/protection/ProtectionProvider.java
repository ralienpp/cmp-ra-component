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
package com.siemens.pki.cmpracomponent.protection;

import java.util.List;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Implementations can control protection of a new generated CMP message
 */
public interface ProtectionProvider {

    ProtectionProvider NO_PROTECTION = new NoProtection();

    /**
     * @return extra certs used for protection
     * @throws Exception in case of error
     */
    List<CMPCertificate> getProtectingExtraCerts() throws Exception;

    /**
     * @return protection algorithm
     */
    AlgorithmIdentifier getProtectionAlg();

    /**
     * build {@link PKIMessage} protection string
     *
     * @param protectedPart message part covered by protection
     * @return the protection string
     * @throws Exception in case of error
     */
    DERBitString getProtectionFor(ProtectedPart protectedPart) throws Exception;

    /**
     * @return sender to use for protected message
     */
    GeneralName getSender();

    /**
     * @return sender KID to use for protected message
     */
    DEROctetString getSenderKID();

    /**
     * do we need an initial GENM/GENP exchange to establish protection?
     *
     * @return <code>true</code> if initial GENM/GENP exchange is needed
     */
    default boolean needsClientInitialKemSetup() {
        return false;
    }
}
