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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext.TemplateExtension;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CrlUpdateRetrievalHandler;
import com.siemens.pki.cmpracomponent.configuration.GetCaCertificatesHandler;
import com.siemens.pki.cmpracomponent.configuration.GetCertificateRequestTemplateHandler;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.cryptoservices.CmsDecryptor;
import com.siemens.pki.cmpracomponent.cryptoservices.DataSignVerifier;
import com.siemens.pki.cmpracomponent.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.MacProtection;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.protection.SignatureBasedProtection;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CRLSource;
import org.bouncycastle.asn1.cmp.CRLStatus;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertReqTemplateContent;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RootCaKeyUpdateContent;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a CMP client implementation
 *
 */
public class CmpClient
        implements CrlUpdateRetrievalHandler,
                GetCaCertificatesHandler,
                GetCertificateRequestTemplateHandler,
                GetRootCaCertificateUpdateHandler {
    /**
     * result of an enrollment transaction
     *
     */
    public interface EnrollmentResult {
        /**
         * get enrolled certificate
         *
         * @return the enrolled certificate
         */
        X509Certificate getEnrolledCertificate();

        /**
         * get certificate chain (1st intermediate certificate up to root certificate)
         * of the enrolled certificate
         *
         * @return the certificate chain of the enrolled certificate
         */
        List<X509Certificate> getEnrollmentChain();

        /**
         * get private key related to the enrolled certificate
         *
         * @return the private key related to the enrolled certificate
         */
        PrivateKey getPrivateKey();
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpClient.class);

    private final ClientRequestHandler requestHandler;

    private final ClientContext clientContext;

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
    public CmpClient(
            final UpstreamExchange upstreamExchange,
            final CmpMessageInterface upstreamConfiguration,
            final ClientContext clientContext)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        requestHandler = new ClientRequestHandler(upstreamExchange, upstreamConfiguration, clientContext);
        this.clientContext = clientContext;
    }

    private ArrayList<X509Certificate> fetchCaCertificatesFromValue(final ASN1Encodable infoValue) {
        if (infoValue == null) {
            return null;
        }
        final ASN1Sequence certificates = ASN1Sequence.getInstance(infoValue);
        final ArrayList<X509Certificate> ret = new ArrayList<>(certificates.size());
        certificates.forEach(x -> {
            try {
                ret.add(CertUtility.asX509Certificate(x.toASN1Primitive().getEncoded()));
            } catch (CertificateException | IOException e) {
                throw new RuntimeException("error decoding certificate", e);
            }
        });
        return ret;
    }

    /**
     * invoke a Get CA certificates GENM request {@inheritDoc}
     */
    @Override
    public List<X509Certificate> getCaCertificates() {
        final PKIBody requestBody = new PKIBody(
                PKIBody.TYPE_GEN_MSG, new GenMsgContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_caCerts)));
        try {
            final PKIBody responseBody = requestHandler.sendReceiveInitialBody(requestBody);
            if (responseBody.getType() == PKIBody.TYPE_GEN_REP) {
                final GenRepContent content = (GenRepContent) responseBody.getContent();
                final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
                if (itav != null) {
                    for (final InfoTypeAndValue aktitav : itav) {
                        if (CMPObjectIdentifiers.id_it_caCerts.equals(aktitav.getInfoType())) {
                            return fetchCaCertificatesFromValue(aktitav.getInfoValue());
                        }
                    }
                }
            }
            logUnexpectedResponse(requestBody);
        } catch (final Exception e) {
            throw new RuntimeException("error processing getCaCertificates", e);
        }
        return null;
    }

    /**
     * invoke a Get certificate request template GENM request {@inheritDoc}
     */
    @Override
    public byte[] getCertificateRequestTemplate() {
        final PKIBody requestBody = new PKIBody(
                PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_certReqTemplate)));
        try {
            final PKIBody responseBody = requestHandler.sendReceiveInitialBody(requestBody);
            if (responseBody.getType() == PKIBody.TYPE_GEN_REP) {
                final GenRepContent content = (GenRepContent) responseBody.getContent();
                final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
                if (itav != null) {
                    for (final InfoTypeAndValue aktitav : itav) {
                        if (CMPObjectIdentifiers.id_it_certReqTemplate.equals(aktitav.getInfoType())) {
                            final ASN1Encodable infoValue = aktitav.getInfoValue();
                            if (infoValue == null) {
                                return null;
                            }
                            return CertReqTemplateContent.getInstance(infoValue).getEncoded();
                        }
                    }
                }
            }
            logUnexpectedResponse(responseBody);
        } catch (final Exception e) {
            throw new RuntimeException("error processing getCertificateRequestTemplate", e);
        }
        return null;
    }

    @Override
    public List<X509CRL> getCrls(
            final String[] dpnFullName,
            final String dpnNameRelativeToCRLIssuer,
            final String[] issuer,
            final Date thisUpdate) {

        if (dpnFullName != null && dpnNameRelativeToCRLIssuer != null) {
            throw new IllegalArgumentException("only dpnFullName OR dpnNameRelativeToCRLIssuer is allowed");
        }

        DistributionPointName dpn = null;
        if (dpnFullName != null) {
            dpn = new DistributionPointName(new GeneralNames(Arrays.stream(dpnFullName)
                    .map(X500Name::new)
                    .map(GeneralName::new)
                    .toArray(GeneralName[]::new)));
        } else if (dpnNameRelativeToCRLIssuer != null) {
            dpn = new DistributionPointName(
                    DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER,
                    new X500Name(dpnNameRelativeToCRLIssuer).getRDNs()[0]);
        }

        final GeneralNames issuers = ifNotNull(
                issuer,
                x -> new GeneralNames(Arrays.stream(x)
                        .map(X500Name::new)
                        .map(GeneralName::new)
                        .toArray(GeneralName[]::new)));

        final CRLStatus crlStatus = new CRLStatus(new CRLSource(dpn, issuers), ifNotNull(thisUpdate, Time::new));

        final PKIBody requestBody = new PKIBody(
                PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(
                        new InfoTypeAndValue(CMPObjectIdentifiers.id_it_crlStatusList, new DERSequence(crlStatus))));
        try {
            final PKIBody responseBody = requestHandler.sendReceiveInitialBody(requestBody);
            if (responseBody.getType() == PKIBody.TYPE_GEN_REP) {
                final GenRepContent content = (GenRepContent) responseBody.getContent();
                final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
                if (itav != null) {
                    for (final InfoTypeAndValue aktitav : itav) {
                        if (CMPObjectIdentifiers.id_it_crls.equals(aktitav.getInfoType())) {
                            final ASN1Encodable infoValue = aktitav.getInfoValue();
                            if (infoValue == null) {
                                return null;
                            }
                            final CertificateFactory certificateFactory = CertUtility.getCertificateFactory();
                            final ASN1Sequence crls = ASN1Sequence.getInstance(infoValue);
                            final List<X509CRL> ret = new ArrayList<>(crls.size());
                            for (final ASN1Encodable aktCrl : crls) {
                                ret.add((X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(
                                        aktCrl.toASN1Primitive().getEncoded())));
                            }
                            return ret;
                        }
                    }
                }
            }
            logUnexpectedResponse(responseBody);
        } catch (final Exception e) {
            throw new RuntimeException("error processing getCertificateRequestTemplate", e);
        }
        return null;
    }

    /**
     * invoke a Get root CA certificate update GENM request {@inheritDoc}
     */
    @Override
    public RootCaCertificateUpdateResponse getRootCaCertificateUpdate(final X509Certificate oldRootCaCertificate) {

        try {
            final PKIBody requestBody = new PKIBody(
                    PKIBody.TYPE_GEN_MSG,
                    new GenMsgContent(new InfoTypeAndValue(
                            CMPObjectIdentifiers.id_it_rootCaCert,
                            ifNotNull(oldRootCaCertificate, cert -> CMPCertificate.getInstance(cert.getEncoded())))));
            final PKIBody responseBody = requestHandler.sendReceiveInitialBody(requestBody);
            if (responseBody.getType() == PKIBody.TYPE_GEN_REP) {
                final GenRepContent content = (GenRepContent) responseBody.getContent();
                final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
                if (itav != null) {
                    for (final InfoTypeAndValue aktitav : itav) {
                        if (CMPObjectIdentifiers.id_it_rootCaKeyUpdate.equals(aktitav.getInfoType())) {
                            final ASN1Encodable infoValue = aktitav.getInfoValue();
                            if (infoValue == null) {
                                return null;
                            }
                            final RootCaKeyUpdateContent ret = RootCaKeyUpdateContent.getInstance(infoValue);

                            return new RootCaCertificateUpdateResponse() {

                                @Override
                                public X509Certificate getNewWithNew() {
                                    try {
                                        return ifNotNull(ret.getNewWithNew(), CertUtility::asX509Certificate);
                                    } catch (final CertificateException e) {
                                        throw new RuntimeException(e);
                                    }
                                }

                                @Override
                                public X509Certificate getNewWithOld() {
                                    try {
                                        return ifNotNull(ret.getNewWithOld(), CertUtility::asX509Certificate);
                                    } catch (final CertificateException e) {
                                        throw new RuntimeException(e);
                                    }
                                }

                                @Override
                                public X509Certificate getOldWithNew() {
                                    try {
                                        return ifNotNull(ret.getOldWithNew(), CertUtility::asX509Certificate);
                                    } catch (final CertificateException e) {
                                        throw new RuntimeException(e);
                                    }
                                }
                            };
                        }
                    }
                }
            }
            logUnexpectedResponse(responseBody);
        } catch (final Exception e) {
            throw new RuntimeException("error processing getCertificateRequestTemplate", e);
        }
        return null;
    }

    private boolean grantsImplicitConfirm(final PKIMessage msg) {
        final InfoTypeAndValue[] generalInfo = msg.getHeader().getGeneralInfo();
        if (generalInfo == null) {
            return false;
        }
        for (final InfoTypeAndValue aktGenInfo : generalInfo) {
            if (aktGenInfo.getInfoType().equals(CMPObjectIdentifiers.it_implicitConfirm)) {
                return true;
            }
        }
        return false;
    }

    /**
     * invoke a IR or CR enrollment transaction
     *
     * @return result of successful enrollment transaction or <code>null</code>
     */
    public EnrollmentResult invokeEnrollment() {

        try {
            final EnrollmentContext enrollmentContext = clientContext.getEnrollmentContext();

            final KeyPair certificateKeypair = enrollmentContext.getCertificateKeypair();
            final CertTemplateBuilder ctb = new CertTemplateBuilder()
                    .setSubject(ifNotNull(enrollmentContext.getSubject(), X500Name::new))
                    .setPublicKey(ifNotNull(
                            certificateKeypair,
                            kp -> SubjectPublicKeyInfo.getInstance(
                                    kp.getPublic().getEncoded())));
            final List<TemplateExtension> templateExtensions = enrollmentContext.getExtensions();
            if (templateExtensions != null) {
                final Extension[] extensions = new Extension[templateExtensions.size()];
                int aktIndex = 0;
                for (final TemplateExtension aktTemplateExtension : templateExtensions) {
                    extensions[aktIndex++] = new Extension(
                            new ASN1ObjectIdentifier(aktTemplateExtension.getId()),
                            aktTemplateExtension.isCritical(),
                            aktTemplateExtension.getValue());
                }
                ctb.setExtensions(new Extensions(extensions));
            }

            PrivateKey enrolledPrivateKey = null;
            if (certificateKeypair != null) {
                enrolledPrivateKey = certificateKeypair.getPrivate();
            }

            final Controls controls = ifNotNull(
                    enrollmentContext.getOldCert(),
                    oldCert -> new Controls(new AttributeTypeAndValue(
                            CMPObjectIdentifiers.regCtrl_oldCertID,
                            new CertId(
                                    new GeneralName(new X500Name(
                                            oldCert.getIssuerX500Principal().getName())),
                                    oldCert.getSerialNumber()))));

            final int enrollmentType = enrollmentContext.getEnrollmentType();
            final PKIBody requestBody =
                    PkiMessageGenerator.generateIrCrKurBody(enrollmentType, ctb.build(), controls, enrolledPrivateKey);

            final PKIMessage responseMessage = requestHandler.sendReceiveValidateMessage(
                    requestHandler.buildInitialRequest(requestBody, enrollmentContext.getRequestImplictConfirm()),
                    enrollmentType);
            final PKIBody responseBody = responseMessage.getBody();
            if (responseBody.getType() != requestBody.getType() + 1) {
                logUnexpectedResponse(responseBody);
                return null;
            }
            final CertRepMessage certRepMessage = (CertRepMessage) responseBody.getContent();
            final CertResponse certResponse = certRepMessage.getResponse()[0];

            final int status = certResponse.getStatus().getStatus().intValue();
            if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
                logUnexpectedResponse(responseBody);
                return null;
            }
            final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
            final CMPCertificate enrolledCertificate =
                    certifiedKeyPair.getCertOrEncCert().getCertificate();

            if (enrolledPrivateKey == null) {
                // central key generation in place, decrypt private key
                CmsDecryptor decryptor = null;
                final ProtectionProvider outputProtection = requestHandler.getOutputProtection();
                if (outputProtection instanceof SignatureBasedProtection) {
                    final SignatureBasedProtection sigProtector = (SignatureBasedProtection) outputProtection;
                    decryptor = new CmsDecryptor(sigProtector.getEndCertificate(), sigProtector.getPrivateKey(), null);
                } else if (outputProtection instanceof MacProtection) {
                    final MacProtection macProtector = (MacProtection) outputProtection;
                    decryptor = new CmsDecryptor(
                            null, null, AlgorithmHelper.convertSharedSecretToPassword(macProtector.getSharedSecret()));
                } else {
                    LOGGER.error("wrong or missing local credentials, no key decryption possible");
                    return null;
                }
                final DataSignVerifier verifier = new DataSignVerifier(requestHandler.getInputVerification());
                enrolledPrivateKey = verifier.verifySignedKey(decryptor.decrypt(EnvelopedData.getInstance(
                        certifiedKeyPair.getPrivateKey().getValue())));
            }
            if (!grantsImplicitConfirm(responseMessage) || !enrollmentContext.getRequestImplictConfirm()) {
                final PKIMessage certConf = requestHandler.buildFurtherRequest(
                        responseMessage, PkiMessageGenerator.generateCertConfBody(enrolledCertificate));
                final PKIMessage pkiConf = requestHandler.sendReceiveValidateMessage(certConf, enrollmentType);
                final PKIBody pkiConfBody = pkiConf.getBody();
                if (pkiConfBody.getType() != PKIBody.TYPE_CONFIRM) {
                    logUnexpectedResponse(pkiConfBody);
                    return null;
                }
            }

            final PrivateKey returnedPrivateKey = enrolledPrivateKey;

            return new EnrollmentResult() {

                @Override
                public X509Certificate getEnrolledCertificate() {
                    try {
                        return CertUtility.asX509Certificate(enrolledCertificate);
                    } catch (final CertificateException e) {
                        return null;
                    }
                }

                @Override
                public List<X509Certificate> getEnrollmentChain() {
                    final List<X509Certificate> ret = new ArrayList<>();
                    try {
                        ret.addAll(new TrustCredentialAdapter(enrollmentContext.getEnrollmentTrust())
                                .validateCertAgainstTrust(
                                        getEnrolledCertificate(),
                                        CertUtility.asX509Certificates(responseMessage.getExtraCerts())));
                        return ret;
                    } catch (final CertificateException e) {
                        LOGGER.error("error building enrollment chain", e);
                        return null;
                    }
                }

                @Override
                public PrivateKey getPrivateKey() {
                    return returnedPrivateKey;
                }
            };

        } catch (final Exception e) {
            throw new RuntimeException("error processing invokeEnrollment", e);
        }
    }

    /**
     * invoke a revocation transaction
     *
     * @return <code>true</code> on success, <code>false</code> on failure
     */
    public boolean invokeRevocation() {
        final RevocationContext revocationContext = clientContext.getRevocationContext();
        try {
            final PKIBody rrBody = PkiMessageGenerator.generateRrBody(
                    new X500Name(revocationContext.getIssuer()),
                    new ASN1Integer(revocationContext.getSerialNumber()),
                    revocationContext.getRevocationReason());
            final PKIBody responseBody = requestHandler.sendReceiveInitialBody(rrBody);
            if (responseBody.getType() == PKIBody.TYPE_REVOCATION_REP) {
                final RevRepContent revRepContent = (RevRepContent) responseBody.getContent();
                return revRepContent.getStatus()[0].getStatus().intValue() == PKIStatus.GRANTED;
            }
            logUnexpectedResponse(responseBody);
        } catch (final Exception e) {
            throw new RuntimeException("error processing invokeRevocation", e);
        }
        return false;
    }

    private void logUnexpectedResponse(final PKIBody body) {
        LOGGER.warn("got unexpected response: " + MessageDumper.msgTypeAsString(body.getType()));
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("message body: \n" + MessageDumper.dumpAsn1Object(body));
        }
    }
}
