package org.diennea;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SSLCertificateGenerator {

    public static X509Certificate generateSelfSignedCertificate(String commonName, final KeyPair keyPair) throws Exception {
        // Set certificate validity
        Date now = new Date();
        Date validity = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year

        // Create X500Name for the certificate
        X500Name issuer = new X500Name("CN=" + commonName);

        // Create the certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                now,
                validity,
                issuer,
                keyPair.getPublic()
        );

        // Add extensions (e.g., KeyUsage, SubjectAlternativeName)
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Add SubjectAlternativeName for localhost
        GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, commonName));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, subjectAltName);

        // Create content signer
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        // Generate the certificate
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
