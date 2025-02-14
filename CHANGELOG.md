# CmpRaComponent changelog

### 1.0.0 (Aug 16 2022)

Initial release on github.

### 1.0.1 (Aug 30 2022)

Fix some SonarLint complains.

### 1.0.2 (Aug 31 2022)

error message improved

### 1.0.3 (Aug 31 2022)

fix: validation of request/response type in case of CKG and delayed delivery
fix: drop root certificates from provided signing/protecting cert chains

### 1.0.4 (Sep 1 2022)

fix: inconsistent config handling for incoming upstream messages

### 1.0.6 (Oct 5 2022)

fix: ASN.1 type of CertProfileValue must be a SEQUENCE (of UTF8String)

### 2.0.0 (Oct 5 2022)

feat:  Let upstreamExchange depend on bodyType

### 2.1.0 (Oct 6 2022)

feat: Selection of central key generation variant should be dynamically

### 2.1.1 (Oct 13 2022)

fix: some minor issues

### 2.1.2 (Oct 18 2022)

fix: Poor and misleading error message

### 2.1.3 (Oct 18 2022)

fix: use ECDH_SHA224KDF as default KeyAgreementAlg

### 2.1.4 (Oct 19 2022)

fix: misleading error messages

### 2.1.5 (Oct 25 2022)

fix: report re-protection without given credentials

### 2.1.6 (Nov 22 2022)

fix: change default provider to BC provider for content verification

### 2.1.7 (Nov 29 2022)

fix: TODOs in InventoryInterface.java, wrong OID for rsaKeyLen

### 2.2.0 (Dec 06 2022)
feat: more sophisticated DPN handling in CrlUpdateRerival

### 2.2.1 (Dec 20 2022)

fix: Improve choice of key management technique for CKG, fix NPE

### 2.2.2 (Jan 30 2023)

feat: Enforce automatic formatting of the code via Spotless

### 2.3.0 (Feb 28 2023)
feat: implement transaction expiration

### 2.4.0 (Mar 14 2023)
fix: rename DownstreamExpirationTime to TransactionMaxLifetime

### 2.5.0 (Mar 21 2023)
fix: rename TransactionMaxLifetime to DownstreamTimeout
