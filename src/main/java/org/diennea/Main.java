///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS io.projectreactor.netty:reactor-netty-core:1.1.7
//DEPS io.projectreactor.netty:reactor-netty-http:1.1.7
//DEPS io.netty:netty-tcnative-boringssl-static:2.0.61.Final
//DEPS org.bouncycastle:bcpkix-jdk15on:1.70
//DEPS org.bouncycastle:bcprov-jdk15on:1.70

package org.diennea;

import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.server.HttpServer;

public class Main {

    private static final String COMMON_NAME = "localhost";
    private static final int PORT = 8443;
    private static final String[] TLS_PROTOCOLS = {"TLSv1.3", "TLSv1.2"};
    private static final String KEY_ALGORITHM = "RSA";
    private static final HttpProtocol[] HTTP_PROTOCOLS = {HttpProtocol.HTTP11, HttpProtocol.H2};

    public static void main(String[] args) throws Exception {
        final var sslContext = createSslContext();

        HttpServer.create()
                .port(PORT)
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
                .protocol(HTTP_PROTOCOLS)
                .handle((request, response) -> response.sendString(Mono.just("Hello over HTTPS with HTTP/2!")))
                .bindNow()
                .onDispose()
                .block();
    }

    private static SslContext createSslContext() throws Exception {
        final var keyPair = generateKeyPair();
        final var certificate = generateSelfSignedCertificate(keyPair);

        return SslContextBuilder
                .forServer(keyPair.getPrivate(), certificate)
                .protocols(TLS_PROTOCOLS)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        // NO_ADVERTISE means do not send the protocol name if it's unsupported
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        // ACCEPT means select the first protocol if no match is found
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2,
                        ApplicationProtocolNames.HTTP_1_1
                ))
                .build();
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate generateSelfSignedCertificate(final KeyPair keyPair) throws Exception {
        final var issuer = new X500Name("CN=" + Main.COMMON_NAME);
        final var serial = BigInteger.valueOf(System.currentTimeMillis());
        final var now = new Date();
        final var validity = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year
        final var publicKey = keyPair.getPublic();

        final var certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, now, validity, issuer, publicKey);

        final var extUtils = new JcaX509ExtensionUtils();
        final var subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(publicKey);
        final var subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, Main.COMMON_NAME));
        final var keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        certBuilder
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                .addExtension(Extension.keyUsage, true, keyUsage)
                .addExtension(Extension.subjectAlternativeName, false, subjectAltName);

        final var signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
