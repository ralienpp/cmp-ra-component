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
package com.siemens.pki.cmpclientcomponent.main;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msggeneration.HeaderProvider;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageBodyValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageHeaderValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.ProtectionValidator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.protection.ProtectionProviderFactory;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 *
 * low level client request functions
 *
 */
class ClientRequestHandler {

    private static final int DEFAULT_PVNO = PKIHeader.CMP_2000;

    private static final String INTERFACE_NAME = "CMP interface";

    private final UpstreamExchange upstreamExchange;

    private final GeneralName recipient;

    private final ProtectionProvider outputProtection;

    private final String certProfile;

    final MessageHeaderValidator headerValidator = new MessageHeaderValidator(INTERFACE_NAME);

    private final ProtectionValidator protectionValidator;

    private final MessageBodyValidator bodyValidator;

    /**
     * @param upstreamExchange      the {@link UpstreamExchange} interface
     *                              implemented by the wrapping application.
     *
     * @param upstreamConfiguration configuration for the upstream CMP interface
     *                              towards the CA
     *
     * @param clientContext         client specific configuration
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    ClientRequestHandler(
            final UpstreamExchange upstreamExchange,
            final CmpMessageInterface upstreamConfiguration,
            final ClientContext clientContext)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        this.upstreamExchange = upstreamExchange;
        recipient = new GeneralName(new X500Name(clientContext.getRecipient()));
        certProfile = clientContext.getCertProfile();
        outputProtection =
                ProtectionProviderFactory.createProtectionProvider(upstreamConfiguration.getOutputCredentials());
        inputVerification = upstreamConfiguration.getInputVerification();
        protectionValidator = new ProtectionValidator(INTERFACE_NAME, inputVerification);
        bodyValidator = new MessageBodyValidator(INTERFACE_NAME, (x, y) -> false, upstreamConfiguration, certProfile);
    }

    private VerificationContext inputVerification;

    PKIBody sendReceiveInitialBody(final PKIBody body, boolean withImplicitConfirm) throws Exception {
        return sendReceiveValidateMessage(buildInitialRequest(body, withImplicitConfirm))
                .getBody();
    }

    PKIMessage buildInitialRequest(final PKIBody requestBody, boolean withImplicitConfirm) throws Exception {
        return buildInitialRequest(requestBody, withImplicitConfirm, DEFAULT_PVNO);
    }

    private PKIMessage buildInitialRequest(final PKIBody requestBody, boolean withImplicitConfirm, final int pvno)
            throws Exception {
        return buildRequest(
                requestBody, new DEROctetString(CertUtility.generateRandomBytes(16)), null, pvno, withImplicitConfirm);
    }

    PKIMessage buildFurtherRequest(PKIMessage formerResponse, PKIBody requestBody) throws Exception {
        final PKIHeader formerResponseHeader = formerResponse.getHeader();
        return buildRequest(
                requestBody,
                formerResponseHeader.getTransactionID(),
                formerResponseHeader.getSenderNonce().getOctets(),
                formerResponseHeader.getPvno().intValueExact(),
                false);
    }

    private PKIMessage buildRequest(
            final PKIBody body,
            final ASN1OctetString transactionId,
            final byte[] recipNonce,
            final int pvno,
            boolean withImplicitConfirm)
            throws Exception {
        final HeaderProvider headerProvider = new HeaderProvider() {
            final byte[] senderNonce = CertUtility.generateRandomBytes(16);

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                if (certProfile == null && !withImplicitConfirm) {
                    return null;
                }
                ArrayList<InfoTypeAndValue> genList = new ArrayList<>(2);
                if (certProfile != null) {
                    genList.add(new InfoTypeAndValue(
                            CMPObjectIdentifiers.id_it_certProfile, new DERSequence(new DERUTF8String(certProfile))));
                }
                if (withImplicitConfirm) {
                    genList.add(new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
                }
                return genList.toArray(new InfoTypeAndValue[0]);
            }

            @Override
            public int getPvno() {
                return pvno;
            }

            @Override
            public GeneralName getRecipient() {
                return recipient;
            }

            @Override
            public byte[] getRecipNonce() {
                return recipNonce;
            }

            @Override
            public GeneralName getSender() {
                return null;
            }

            @Override
            public byte[] getSenderNonce() {
                return senderNonce;
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return transactionId;
            }
        };
        return PkiMessageGenerator.generateAndProtectMessage(headerProvider, outputProtection, body);
    }

    PKIMessage sendReceiveValidateMessage(final PKIMessage request) throws Exception {
        final int firstRequestType = request.getBody().getType();
        byte[] rawresponse = upstreamExchange.sendReceiveMessage(request.getEncoded(), certProfile, firstRequestType);
        if (rawresponse == null) {
            return null;
        }
        PKIMessage response = PKIMessage.getInstance(rawresponse);
        validateResponse(response);
        final ASN1OctetString requestSenderNonce = request.getHeader().getSenderNonce();
        final ASN1OctetString recipNonce = response.getHeader().getRecipNonce();
        if (!Objects.equals(requestSenderNonce, recipNonce)) {
            throw new CmpValidationException(
                    INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
        }
        if (!isWaitingIndication(response.getBody())) {
            // no delayed delivery
            return response;
        }
        for (; ; ) {
            // do polling
            PKIMessage pollReq = buildFurtherRequest(response, PkiMessageGenerator.generatePollReq());
            rawresponse = upstreamExchange.sendReceiveMessage(pollReq.getEncoded(), certProfile, firstRequestType);
            if (rawresponse == null) {
                return null;
            }
            response = PKIMessage.getInstance(rawresponse);
            validateResponse(response);
            if (!Objects.equals(requestSenderNonce, recipNonce)
                    && !Objects.equals(pollReq.getHeader().getSenderNonce(), recipNonce)) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
            }
            PKIBody responseBody = response.getBody();
            if (responseBody.getType() != PKIBody.TYPE_POLL_REP) {
                return response;
            }
            int checkAfterTime = ((PollRepContent) responseBody.getContent())
                    .getCheckAfter(0)
                    .intPositiveValueExact();
            Thread.sleep(checkAfterTime * 1000L);
        }
    }

    private boolean isWaitingIndication(PKIBody responseBody) {
        try {
            switch (responseBody.getType()) {
                case PKIBody.TYPE_ERROR:
                    ErrorMsgContent errorContent = (ErrorMsgContent) responseBody.getContent();
                    return errorContent.getPKIStatusInfo().getStatus().intValue() == PKIStatus.WAITING;
                case PKIBody.TYPE_INIT_REP:
                case PKIBody.TYPE_CERT_REP:
                case PKIBody.TYPE_KEY_UPDATE_REP:
                    CertRepMessage certRepMessageContent = (CertRepMessage) responseBody.getContent();
                    return certRepMessageContent
                                    .getResponse()[0]
                                    .getStatus()
                                    .getStatus()
                                    .intValue()
                            == PKIStatus.WAITING;
                default:
                    return false;
            }
        } catch (Exception ex) {
            // not decodable as waiting indication
            return false;
        }
    }

    private void validateResponse(final PKIMessage response) throws BaseCmpException {
        headerValidator.validate(response);
        protectionValidator.validate(response);
        bodyValidator.validate(response);
    }

    ProtectionProvider getOutputProtection() {
        return outputProtection;
    }

    VerificationContext getInputVerification() {
        return inputVerification;
    }
}
