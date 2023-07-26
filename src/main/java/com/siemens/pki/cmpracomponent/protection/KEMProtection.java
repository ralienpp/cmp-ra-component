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
package com.siemens.pki.cmpracomponent.protection;

import com.siemens.pki.cmpracomponent.cmpextension.KemBMParameter;
import com.siemens.pki.cmpracomponent.cmpextension.KemOtherInfo;
import com.siemens.pki.cmpracomponent.cmpextension.NewCMPObjectIdentifiers;
import com.siemens.pki.cmpracomponent.configuration.KEMCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.KdfFunction;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMac;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMacFactory;
import com.siemens.pki.cmpracomponent.msggeneration.HeaderProvider;
import com.siemens.pki.cmpracomponent.persistency.InitialKemContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext.InterfaceContext;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

public class KEMProtection implements ProtectionProvider {

    private final AlgorithmIdentifier kdf;
    private final int keyLen;
    private final AlgorithmIdentifier mac;
    private final PersistencyContext persistencyContext;
    private final InterfaceContext interfaceContext;
    private final PublicKey pubkey;

    KEMProtection(
            final KEMCredentialContext config,
            final PersistencyContext persistencyContext,
            final InterfaceContext interfaceContext)
            throws NoSuchAlgorithmException {
        this.interfaceContext = interfaceContext;
        this.persistencyContext = persistencyContext;
        this.pubkey = config.getPubkey();
        mac = new AlgorithmIdentifier(AlgorithmHelper.getOidForMac(config.getMacAlgorithm()));
        keyLen = config.getkeyLength();
        kdf = AlgorithmHelper.getKdfOID(config.getKdf());
    }

    @Override
    public InfoTypeAndValue[] getGeneralInfo(HeaderProvider headerProvider) throws Exception {
        InitialKemContext initialKemContext = persistencyContext.getInitialKemContext(interfaceContext);
        if (initialKemContext != null) {
            // it_kemCiphertextInfo already known and shared
            return null;
        }
        initialKemContext = new InitialKemContext(
                headerProvider.getTransactionID(),
                headerProvider.getSenderNonce(),
                headerProvider.getRecipNonce(),
                pubkey);
        persistencyContext.setInitialKemContext(initialKemContext, interfaceContext);
        return new InfoTypeAndValue[] {
            new InfoTypeAndValue(NewCMPObjectIdentifiers.it_kemCiphertextInfo, initialKemContext.getCiphertextInfo())
        };
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return new AlgorithmIdentifier(NewCMPObjectIdentifiers.kemBasedMac, new KemBMParameter(kdf, keyLen, mac));
    }

    @Override
    public DERBitString getProtectionFor(ProtectedPart protectedPart) throws Exception {
        final InitialKemContext initialKemContext = persistencyContext.getInitialKemContext(interfaceContext);
        final KemOtherInfo kemOtherInfo = initialKemContext.buildKemOtherInfo(keyLen, mac);
        final KdfFunction kdf = KdfFunction.getKdfInstance(this.kdf);
        final SecretKey key =
                kdf.deriveKey(initialKemContext.getSharedSecret(null), keyLen, null, kemOtherInfo.getEncoded());

        final WrappedMac mac = WrappedMacFactory.createWrappedMac(this.mac, key.getEncoded());
        return new DERBitString(mac.calculateMac(protectedPart.getEncoded(ASN1Encoding.DER)));
    }

    @Override
    public GeneralName getSender() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public DEROctetString getSenderKID() {
        // TODO Auto-generated method stub
        return null;
    }
}
