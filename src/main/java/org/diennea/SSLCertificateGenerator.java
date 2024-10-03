package org.diennea;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SSLCertificateGenerator {

    public static X509Certificate generateSelfSignedCertificate(String commonName, final KeyPair keyPair) throws Exception {
        // Set certificate validity
        Date now = new Date();
        Date validity = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year

        // Create X500Name for the certificate
        X500Name issuer = new X500Name("CN=" + commonName);
        
        // Create the certificate builder
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                now,
                validity,
                issuer,
                keyPair.getPublic()
        );

        // Create content signer
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        // Generate the certificate
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
