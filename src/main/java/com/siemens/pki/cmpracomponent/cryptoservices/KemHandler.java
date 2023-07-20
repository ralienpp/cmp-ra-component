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
package com.siemens.pki.cmpracomponent.cryptoservices;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.KeyGenerator;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class KemHandler {

    /**
     *
     * result of an KEM encapsulation
     *
     */
    public static class EncapResult {
        private final byte[] sharedSecret;
        private final byte[] encapsulated;

        /**
         *
         * @param sharedSecret the shared secret generated during encapsulation
         * @param encapsulated the cipher text generated during encapsulation
         */
        public EncapResult(byte[] sharedSecret, byte[] encapsulated) {
            this.sharedSecret = sharedSecret;
            this.encapsulated = encapsulated;
        }

        /**
         *
         * @return cipher text
         */
        public byte[] getEncapsulated() {
            return encapsulated;
        }

        /**
         *
         * @return shared secret
         */
        public byte[] getSharedSecret() {
            return sharedSecret;
        }
    }

    private static final SecureRandom RANDOMGENERATOR = new SecureRandom();

    private static final String SYMMETRIC_CIPHER = "AES";

    private static final Provider BC_PQ_PROV = new BouncyCastlePQCProvider();

    static {
        Security.addProvider(BC_PQ_PROV);
    }

    private final String kemAlgorithm;
    private final KeyPairGenerator kpg;

    public KemHandler(String kemAlgorithm) throws NoSuchAlgorithmException {
        this.kemAlgorithm = kemAlgorithm;
        kpg = KeyPairGenerator.getInstance(kemAlgorithm, KemHandler.BC_PQ_PROV);
    }

    /**
     * KEM decapsulation
     *
     * @param encapsulation cipher text
     * @param priv          private part of KEM keypair
     * @return shared secret
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    public byte[] decapsulate(byte[] encapsulation, PrivateKey priv)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        final KeyGenerator keyGenReceived = KeyGenerator.getInstance(kemAlgorithm, BC_PQ_PROV);
        keyGenReceived.init(new KEMExtractSpec(priv, encapsulation, SYMMETRIC_CIPHER));
        final SecretKeyWithEncapsulation decapsulated_secret =
                (SecretKeyWithEncapsulation) keyGenReceived.generateKey();
        return decapsulated_secret.getEncoded();
    }

    /**
     * KEM encapsulation
     *
     * @param pub public part of KEM keypair
     * @return shared secret and cipher text
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public EncapResult encapsulate(PublicKey pub)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        final KeyGenerator keyGen = KeyGenerator.getInstance(kemAlgorithm, BC_PQ_PROV);
        keyGen.init(new KEMGenerateSpec(pub, SYMMETRIC_CIPHER), RANDOMGENERATOR);
        final SecretKeyWithEncapsulation encapsulation = (SecretKeyWithEncapsulation) keyGen.generateKey();
        return new EncapResult(encapsulation.getEncoded(), encapsulation.getEncapsulation());
    }

    /**
     * generate new KEM keypair
     *
     * @return new KEM keypair
     */
    public KeyPair generateNewKeypair() {
        return kpg.generateKeyPair();
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() throws NoSuchAlgorithmException {
        return AlgorithmHelper.getKemAlgIdFromName(kemAlgorithm);
    }
}
