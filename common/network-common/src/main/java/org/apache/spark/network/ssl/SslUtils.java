/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.network.ssl;


import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLPeerUnverifiedException;

import io.netty.handler.ssl.SslHandler;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.spark.network.util.*;

/**
 * Utility functions for working with SSL.
 */
class KeypairAndCert {
  private final KeyPair keypair;
  private final X509Certificate cert;

  public KeypairAndCert(KeyPair keypair, X509Certificate cert) {
    this.keypair = keypair;
    this.cert = cert;
  }

  public KeyPair getKeypair() {
    return keypair;
  }

  public X509Certificate getCert() {
    return cert;
  }

}

public class SslUtils {

  private static final Logger logger = LoggerFactory.getLogger(SslUtils.class);

  private static int CERT_EXPIRY_DAYS = 730;
  private static String HMAC_ALGORITHM = "HMacSHA256";
  private static String KEY_ALGORITHM = "ECDSA";
  private static String SIGNATURE_ALGORITHM = "SHA256withECDSA";
  private static String BOUNCY_CASTLE_PROVIDER = "BC";
  private static String SAN_IDENTIFIER = "spark-shared-secret-mac-";

  // TODO:
  public static boolean verifySinglePeerCert(String sharedSecret, X509Certificate cert) {
    try {
      BigInteger serialNumber = cert.getSerialNumber();
      Collection<List<?>> sans = cert.getSubjectAlternativeNames();
      if (sans != null) {
        return sans
                .stream()
                .filter(san -> {
                  String toMatch = (String) san.get(1);
                  if (toMatch.startsWith(SAN_IDENTIFIER)) {
                    try {
                      return verifyHmac(serialNumber, toMatch, sharedSecret);
                    } catch (Exception ex) {
                      return false;
                    }
                  }
                  return false;
                }).count() > 0;
      }
    } catch (CertificateParsingException ex){
      // swallow
    }
    return false;
  }

  // REMOVE BEFORE MERGE: Ask Steve if we need to run the secret through an hkdf
  public static String generateHmacWithSharedSecret(
    BigInteger sn, String sharedSecret
  ) throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret.getBytes(), HMAC_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_ALGORITHM);
    mac.init(secretKeySpec);
    byte[] hmacBytes = mac.doFinal(sn.toByteArray());
    String base64Hmac = Base64.getEncoder().encodeToString(hmacBytes);
    logger.info("REMOVE BEFORE MERGE Generated HMAC: " + SAN_IDENTIFIER + base64Hmac);
    return SAN_IDENTIFIER + base64Hmac;
  }

  public static boolean verifyHmac(BigInteger serialNumber, String receivedBase64Hmac, String sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret.getBytes(), HMAC_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_ALGORITHM);
    mac.init(secretKeySpec);
    byte[] hmacBytes = mac.doFinal(serialNumber.toByteArray());
    String calculatedBase64Hmac = SAN_IDENTIFIER + Base64.getEncoder().encodeToString(hmacBytes);
    logger.info("REMOVE BEFORE MERGE Verifying hmac " + calculatedBase64Hmac + " against " + receivedBase64Hmac);
    return java.security.MessageDigest.isEqual(calculatedBase64Hmac.getBytes(), receivedBase64Hmac.getBytes());
  }

  // TODO: See if there is a better place to do this so we only run this if TLS is
  // enabled? We need to run this just once, I think
  static {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  /**
   * Generate a certificate with a proper shared secret
   */
  public static KeypairAndCert generateKeypairAndCert(
    String sharedSecret
  ) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
           OperatorCreationException, CertIOException, CertificateException {

    // Prepare a subject and serial number
    // TODO: Add AppID or something here?
    X500Name subject = new X500Name("CN=Spark-Node");
    BigInteger serialNumber = new BigInteger(64, new SecureRandom());

    // Generate a keypair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
    keyGen.initialize(256);
    KeyPair keyPair = keyGen.genKeyPair();

    // Set expiry dates
    Date from = new Date();
    Date to = new Date(from.getTime() + CERT_EXPIRY_DAYS * 86400000L);

    // Create a certificate builder
    JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
    ContentSigner csrContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
      .setProvider(BOUNCY_CASTLE_PROVIDER)
      .build(keyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
    X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
      subject,
      serialNumber,
      from,
      to,
      csr.getSubject(),
      csr.getSubjectPublicKeyInfo()
    );
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

    // Certificate extensions to adhere to standards (https://www.rfc-editor.org/rfc/rfc5280)
    // This is a root CA since we're using it to sign itself
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));
    certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
    certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement));

    // Add a SAN with an HMAC of the shared secret to prove we know it.
    String hmac = generateHmacWithSharedSecret(serialNumber, sharedSecret);
    DERSequence sans = new DERSequence(new ASN1Encodable[] {
      new GeneralName(GeneralName.dNSName, hmac),
    });
    certBuilder.addExtension(Extension.subjectAlternativeName, true, sans);

    X509Certificate cert = new JcaX509CertificateConverter()
      .setProvider(BOUNCY_CASTLE_PROVIDER)
      .getCertificate(certBuilder.build(csrContentSigner));

    return new KeypairAndCert(keyPair, cert);
  }
}
