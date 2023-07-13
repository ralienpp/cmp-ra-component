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
package com.siemens.pki.cmpracomponent.persistency;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.siemens.pki.cmpracomponent.cmpextension.KemCiphertextInfo;
import com.siemens.pki.cmpracomponent.cmpextension.KemOtherInfo;
import com.siemens.pki.cmpracomponent.cmpextension.NewCMPObjectIdentifiers;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * holder for all persistent data
 */
public class PersistencyContext {

    public static class InitialKemContext {

        private ASN1OctetString transactionID;

        private ASN1OctetString senderNonce;

        private ASN1OctetString recipNonce;

        private KemCiphertextInfo ciphertextInfo;

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

        public KemOtherInfo buildKemOtherInfo(ASN1Integer len, AlgorithmIdentifier mac) {
            return new KemOtherInfo(transactionID, senderNonce, recipNonce, len, mac, ciphertextInfo.getCt());
        }

        public KemCiphertextInfo getCiphertextInfo() {
            return ciphertextInfo;
        }
    }

    public enum InterfaceKontext {
        dowstream_rec,
        dowstream_send,
        upstream_rec,
        upstream_send
    }

    private static final int InitialKemContexts_SIZE = InterfaceKontext.values().length;

    static InitialKemContext fetchInitialKemContext(PKIMessage msg) {
        final PKIHeader header = msg.getHeader();
        if (header.getGeneralInfo() != null) {
            for (final InfoTypeAndValue itav : header.getGeneralInfo()) {
                if (NewCMPObjectIdentifiers.kemCiphertextInfo.equals(itav.getInfoType())) {
                    return new InitialKemContext(
                            header.getTransactionID(),
                            header.getSenderNonce(),
                            header.getRecipNonce(),
                            KemCiphertextInfo.getInstance(itav.getInfoValue()));
                }
            }
        }
        if (msg.getBody().getType() == PKIBody.TYPE_GEN_MSG || msg.getBody().getType() == PKIBody.TYPE_GEN_REP) {
            for (final InfoTypeAndValue itav : ((GenMsgContent) msg.getBody().getContent()).toInfoTypeAndValueArray()) {
                if (NewCMPObjectIdentifiers.kemCiphertextInfo.equals(itav.getInfoType())) {
                    return new InitialKemContext(
                            header.getTransactionID(),
                            header.getSenderNonce(),
                            header.getRecipNonce(),
                            KemCiphertextInfo.getInstance(itav.getInfoValue()));
                }
            }
        }
        return null;
    }

    private final InitialKemContext InitialKemContexts[] = new InitialKemContext[InitialKemContexts_SIZE];

    @JsonIgnore
    private final TransactionStateTracker transactionStateTracker = new TransactionStateTracker(this);

    private Date expirationTime;

    private byte[] transactionId;
    private String certProfile;
    private PrivateKey newGeneratedPrivateKey;
    private Set<CMPCertificate> alreadySentExtraCerts;
    private PKIMessage initialRequest;
    private PKIMessage pendingDelayedResponse;
    private LastTransactionState lastTransactionState;
    private byte[] lastSenderNonce;
    private byte[] digestToConfirm;
    private boolean implicitConfirmGranted;
    private byte[] requestedPublicKey;

    @JsonIgnore
    private List<CMPCertificate> issuingChain;

    @JsonIgnore
    private PersistencyContextManager contextManager;

    private int certificateRequestType;

    private boolean delayedDeliveryInProgress;

    public PersistencyContext() {}

    PersistencyContext(final PersistencyContextManager contextManager, final byte[] transactionId) {
        this.transactionId = transactionId;
        this.contextManager = contextManager;
        lastTransactionState = LastTransactionState.INITIAL_STATE;
        this.certificateRequestType = -1;
    }

    public void flush() throws IOException {
        if (transactionStateTracker.isTransactionTerminated()) {
            contextManager.clearPersistencyContext(transactionId);
        } else {
            contextManager.flushPersistencyContext(this);
        }
    }

    public Set<CMPCertificate> getAlreadySentExtraCerts() {
        if (alreadySentExtraCerts == null) {
            alreadySentExtraCerts = new HashSet<>();
        }
        return alreadySentExtraCerts;
    }

    public String getCertProfile() {
        return certProfile;
    }

    public boolean getDelayedDeliveryInProgress() {
        return delayedDeliveryInProgress;
    }

    public byte[] getDigestToConfirm() {
        return digestToConfirm;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    public InitialKemContext getInitialKemContext(InterfaceKontext interfaceContext) {
        return InitialKemContexts[interfaceContext.ordinal()];
    }

    public PKIMessage getInitialRequest() {
        return initialRequest;
    }

    public List<CMPCertificate> getIssuingChain() {
        return issuingChain;
    }

    public byte[] getLastSenderNonce() {
        return lastSenderNonce;
    }

    public LastTransactionState getLastTransactionState() {
        return lastTransactionState;
    }

    public PrivateKey getNewGeneratedPrivateKey() {
        return newGeneratedPrivateKey;
    }

    public PKIMessage getPendingDelayedResponse() {
        return pendingDelayedResponse;
    }

    public byte[] getRequestedPublicKey() {
        return requestedPublicKey;
    }

    public int getRequestType() {
        return certificateRequestType;
    }

    public byte[] getTransactionId() {
        return transactionId;
    }

    public boolean isImplicitConfirmGranted() {
        return implicitConfirmGranted;
    }

    public void setAlreadySentExtraCerts(final Set<CMPCertificate> alreadySentExtraCerts) {
        this.alreadySentExtraCerts = alreadySentExtraCerts;
    }

    public void setCertProfile(final String certProfile) {
        if (certProfile != null) {
            this.certProfile = certProfile;
        }
    }

    public void setContextManager(final PersistencyContextManager contextManager) {
        this.contextManager = contextManager;
    }

    public void setDelayedDeliveryInProgress(final boolean delayedDeliveryInProgress) {
        this.delayedDeliveryInProgress = delayedDeliveryInProgress;
    }

    public void setDigestToConfirm(final byte[] digestToConfirm) {
        this.digestToConfirm = digestToConfirm;
    }

    public void setExpirationTime(final Date expirationTime) {
        this.expirationTime = expirationTime;
    }

    public void setImplicitConfirmGranted(final boolean implicitConfirmGranted) {
        this.implicitConfirmGranted = implicitConfirmGranted;
    }

    public void setInitialKemContext(
            InitialKemContext initialKemContext, PersistencyContext.InterfaceKontext interfaceContext)
            throws CmpValidationException {
        if (initialKemContext == null) {
            return;
        }
        final int index = interfaceContext.ordinal();
        if (InitialKemContexts[index] != null) {
            throw new CmpValidationException(
                    getCertProfile(), PKIFailureInfo.badMessageCheck, "unexpected reinitalization of KemOtherInfo");
        }
        InitialKemContexts[index] = initialKemContext;
    }

    public void setInitialKemContext(PKIMessage msg, PersistencyContext.InterfaceKontext interfaceContext)
            throws CmpValidationException {
        final InitialKemContext initialKemContext = fetchInitialKemContext(msg);
        if (initialKemContext != null) {
            setInitialKemContext(initialKemContext, interfaceContext);
        }
    }

    public void setInitialRequest(final PKIMessage initialRequest) {
        this.initialRequest = initialRequest;
    }

    public void setIssuingChain(final List<CMPCertificate> issuingChain) {
        this.issuingChain = issuingChain;
    }

    public void setLastSenderNonce(final byte[] lastSenderNonce) {
        this.lastSenderNonce = lastSenderNonce;
    }

    public void setLastTransactionState(final LastTransactionState lastTransactionState) {
        this.lastTransactionState = lastTransactionState;
    }

    public void setNewGeneratedPrivateKey(final PrivateKey newGeneratedPrivateKey) {
        this.newGeneratedPrivateKey = newGeneratedPrivateKey;
    }

    public void setPendingDelayedResponse(final PKIMessage delayedResponse) throws CmpProcessingException {
        if (this.pendingDelayedResponse != null) {
            throw new CmpProcessingException(
                    "upstream persistency",
                    PKIFailureInfo.transactionIdInUse,
                    "duplicate response for same transactionID");
        }
        this.pendingDelayedResponse = delayedResponse;
    }

    public void setRequestedPublicKey(final byte[] requestedPublicKey) {
        this.requestedPublicKey = requestedPublicKey;
    }

    public void setRequestType(final int certificateRequestType) {
        this.certificateRequestType = certificateRequestType;
    }

    public void trackRequest(final PKIMessage msg) throws BaseCmpException, IOException {
        transactionStateTracker.trackMessage(msg);
    }

    public void trackResponse(final PKIMessage msg) throws BaseCmpException, IOException {
        transactionStateTracker.trackMessage(msg);
    }

    public void updateTransactionExpirationTime(final Date expirationTime) {
        // only downstream can expire
        this.expirationTime = expirationTime;
    }
}
