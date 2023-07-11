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

import java.math.BigInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class KdfFunction {

    public static KdfFunction getKdfInstance(AlgorithmIdentifier keyDerivationFunc) {
        // TODO replace dummy implementation
        return new KdfFunction();
    }

    public SecretKey deriveKey(byte[] sharedSecret, BigInteger keyLength, byte[] context) {
        // TODO replace dummy implementation
        return new SecretKeySpec("A dummy key".getBytes(), "HKDF");
    }
}
