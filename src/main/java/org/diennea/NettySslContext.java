package org.diennea;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class NettySslContext {

    public static SslContext createSslContext(X509Certificate certificate, PrivateKey privateKey) throws Exception {
        // Convert to Netty's SslContext
        return SslContextBuilder.forServer(privateKey, certificate).build();
    }

    public static void main(String[] args) throws Exception {
        String commonName = "localhost"; // Change as needed
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final var keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate cert = SSLCertificateGenerator.generateSelfSignedCertificate(commonName, keyPair);
        
        // Get the private key from the generated key pair (you may need to store it securely)
        PrivateKey privateKey = keyPair.getPrivate(); // Store and retrieve your private key appropriately

        SslContext sslContext = createSslContext(cert, privateKey);
        
        // Now you can use sslContext in your Netty server setup
    }
}
