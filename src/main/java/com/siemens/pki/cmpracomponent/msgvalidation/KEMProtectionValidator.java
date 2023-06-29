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
package com.siemens.pki.cmpracomponent.msgvalidation;

import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.siemens.pki.cmpracomponent.cmpextension.KemBMParameter;
import com.siemens.pki.cmpracomponent.cmpextension.KemCiphertextInfo;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMac;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMacFactory;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;

public class KEMProtectionValidator extends MacValidator {

    private final PersistencyContext persistencyContext;

    public KEMProtectionValidator(
            String interfaceName, VerificationContext config, PersistencyContext persistencyContext) {
        super(interfaceName, config);
        this.persistencyContext = persistencyContext;
    }

    @Override
    public Void validate(final PKIMessage message) throws BaseCmpException {
        try {
            final PKIHeader header = message.getHeader();
            final PrivateKey decapKey = config.getPrivateKemKey();
            final KemCiphertextInfo kemCiphertextInfo = persistencyContext.getDownstreamKemCiphertextInfo();
            final KemBMParameter kemBmpParameter =
                    KemBMParameter.getInstance(header.getProtectionAlg().getParameters());
            final AlgorithmIdentifier keyDerivationFunc = kemBmpParameter.getKdf();
            if (!PKCSObjectIdentifiers.id_PBKDF2.equals(keyDerivationFunc.getAlgorithm())) {
                throw new CmpValidationException(
                        getInterfaceName(),
                        PKIFailureInfo.badMessageCheck,
                        "PBKDF2 protection check failed, unsupported keyDerivationFunc");
            }
            final PBKDF2Params params = PBKDF2Params.getInstance(keyDerivationFunc.getParameters());
            final byte[] sharedSecret = new KemHandler(
                            kemCiphertextInfo.getKem().toString())
                    .decapsulate(kemCiphertextInfo.getCt().getOctets(), decapKey);
            final SecretKeyFactory keyFact = AlgorithmHelper.getSecretKeyFactory(
                    params.getPrf().getAlgorithm().getId());
            final SecretKey key = keyFact.generateSecret(new PBEKeySpec(
                    new String(sharedSecret).toCharArray(),
                    params.getSalt(),
                    params.getIterationCount().intValue(),
                    params.getKeyLength().intValue()));
            final WrappedMac mac = WrappedMacFactory.createWrappedMac(kemBmpParameter.getMac(), key.getEncoded(), persistencyContext.getDownstreamKemOtherInfo().getEncoded());
            final byte[] protectedBytes = new ProtectedPart(header, message.getBody()).getEncoded(ASN1Encoding.DER);
            final byte[] recalculatedProtection = mac.calculateMac(protectedBytes);
            final byte[] protectionBytes = message.getProtection().getBytes();
            if (!Arrays.equals(recalculatedProtection, protectionBytes)) {
                throw new CmpValidationException(
                        getInterfaceName(), PKIFailureInfo.badMessageCheck, "KEM protection check failed");
            }
        } catch (final BaseCmpException cex) {
            throw cex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(
                    getInterfaceName(), PKIFailureInfo.badMessageCheck, ex.getLocalizedMessage());
        }
        return null;
    }
}
