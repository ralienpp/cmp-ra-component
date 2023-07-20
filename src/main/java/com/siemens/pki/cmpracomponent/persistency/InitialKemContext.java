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
package com.siemens.pki.cmpracomponent.persistency;

import com.siemens.pki.cmpracomponent.cmpextension.KemCiphertextInfo;
import com.siemens.pki.cmpracomponent.cmpextension.KemOtherInfo;
import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler;
import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler.EncapResult;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class InitialKemContext {

    private ASN1OctetString transactionID;

    private ASN1OctetString senderNonce;

    private ASN1OctetString recipNonce;

    private KemCiphertextInfo ciphertextInfo;

    private byte[] sharedSecret;

    public InitialKemContext() {}

    public InitialKemContext(
            ASN1OctetString transactionID,
            ASN1OctetString senderNonce,
            ASN1OctetString recipNonce,
            KemCiphertextInfo ciphertextInfo) {
        this.transactionID = transactionID;
        this.senderNonce = senderNonce;
        this.recipNonce = recipNonce;
        this.ciphertextInfo = ciphertextInfo;
    }

    public InitialKemContext(
            ASN1OctetString transactionID, ASN1OctetString senderNonce, ASN1OctetString recipNonce, PublicKey pubkey)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        this.transactionID = transactionID;
        this.senderNonce = senderNonce;
        this.recipNonce = recipNonce;
        final KemHandler kemHandler = new KemHandler(pubkey.getAlgorithm());
        final EncapResult encapResult = kemHandler.encapsulate(pubkey);
        sharedSecret = encapResult.getSharedSecret();
        ciphertextInfo = new KemCiphertextInfo(
                kemHandler.getAlgorithmIdentifier(), new BEROctetString(encapResult.getEncapsulated()));
    }

    public KemOtherInfo buildKemOtherInfo(long keyLen, AlgorithmIdentifier mac) {
        return new KemOtherInfo(transactionID, senderNonce, recipNonce, keyLen, mac, ciphertextInfo.getCt());
    }

    public KemCiphertextInfo getCiphertextInfo() {
        return ciphertextInfo;
    }

    public ASN1OctetString getRecipNonce() {
        return recipNonce;
    }

    public ASN1OctetString getSenderNonce() {
        return senderNonce;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public byte[] getSharedSecret(PrivateKey key) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        if (sharedSecret == null) {
            sharedSecret = new KemHandler(ciphertextInfo.getKem().getAlgorithm().toString())
                    .decapsulate(ciphertextInfo.getCt().getOctets(), key);
        }
        return sharedSecret;
    }

    public ASN1OctetString getTransactionID() {
        return transactionID;
    }

    public void setCiphertextInfo(KemCiphertextInfo ciphertextInfo) {
        this.ciphertextInfo = ciphertextInfo;
    }

    public void setRecipNonce(ASN1OctetString recipNonce) {
        this.recipNonce = recipNonce;
    }

    public void setSenderNonce(ASN1OctetString senderNonce) {
        this.senderNonce = senderNonce;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void setTransactionID(ASN1OctetString transactionID) {
        this.transactionID = transactionID;
    }
}
