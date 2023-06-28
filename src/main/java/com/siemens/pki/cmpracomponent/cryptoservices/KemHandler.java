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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class KemHandler {

    public static Provider prov = new BouncyCastlePQCProvider();

    {
        Security.addProvider(prov);
    }

    public static class EncapResult {
        byte[] sharedSecret;
        byte[] encapsulated;

        /**
         *
         * @param sharedSecret
         * @param encapsulated cipher text
         */
        public EncapResult(byte[] sharedSecret, byte[] encapsulated) {
            this.sharedSecret = sharedSecret;
            this.encapsulated = encapsulated;
        }

        public byte[] getSharedSecret() {
            return sharedSecret;
        }

        public byte[] getEncapsulated() {
            return encapsulated;
        }
    }

    public static EncapResult encapsulate(PublicKey pub)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", prov);
        keyGen.init(new KEMGenerateSpec(pub, "AES"), new SecureRandom());
        SecretKeyWithEncapsulation encapsulation = (SecretKeyWithEncapsulation) keyGen.generateKey();
        return new EncapResult(encapsulation.getEncoded(), encapsulation.getEncapsulation());
    }

    public static byte[] decapsulate(byte[] encapsulation, PrivateKey priv)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyGenerator keyGenReceived = KeyGenerator.getInstance("Kyber", prov);
        keyGenReceived.init(new KEMExtractSpec(priv, encapsulation, "AES"));
        SecretKeyWithEncapsulation decapsulated_secret = (SecretKeyWithEncapsulation) keyGenReceived.generateKey();
        return decapsulated_secret.getEncoded();
    }
}
