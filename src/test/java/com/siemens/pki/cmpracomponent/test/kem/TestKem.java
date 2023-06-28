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
package com.siemens.pki.cmpracomponent.test.kem;

import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler;
import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler.EncapResult;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import org.junit.Test;

public class TestKem {

    @Test
    public void testKem() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator kpg_alice = KeyPairGenerator.getInstance("Kyber", KemHandler.prov);
        KeyPair keyPair_alice = kpg_alice.generateKeyPair();
        // encapsulation
        EncapResult encResult = KemHandler.encapsulate(keyPair_alice.getPublic());
        byte[] bob_shared = encResult.getSharedSecret();
        byte[] encapsulated = encResult.getEncapsulated();
        // decapsulation
        byte[] alice_shared = KemHandler.decapsulate(encapsulated, keyPair_alice.getPrivate());
        assertTrue(Arrays.equals(bob_shared, alice_shared));
    }
}
