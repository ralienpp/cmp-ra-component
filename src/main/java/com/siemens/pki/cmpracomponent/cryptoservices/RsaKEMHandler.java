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
import java.security.PublicKey;
import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

public class RsaKEMHandler extends KemHandler {

    private final Digest hasher = new SHA256Digest();

    private final KDF2BytesGenerator kdf = new KDF2BytesGenerator(hasher);
    private final RSAKEMGenerator encapsulator = new RSAKEMGenerator(32, kdf, new SecureRandom());

    public RsaKEMHandler(String kemAlgorithm) throws NoSuchAlgorithmException {
        super(kemAlgorithm, KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048));
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation, PrivateKey priv)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // TODO ALEX
        // RSAKEMExtractor(RSAKeyParameters var1, int var2, DerivationFunction var3)
        return null;
    }

    @Override
    public SecretWithEncapsulation encapsulate(PublicKey pub)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        final RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
                false, ((BCRSAPublicKey) pub).getModulus(), ((BCRSAPublicKey) pub).getPublicExponent());
        return encapsulator.generateEncapsulated(rsaKeyParameters);
    }
}
