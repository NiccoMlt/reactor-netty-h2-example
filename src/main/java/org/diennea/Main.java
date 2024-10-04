///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS io.projectreactor.netty:reactor-netty-core:1.1.7
//DEPS io.projectreactor.netty:reactor-netty-http:1.1.7
//DEPS io.netty:netty-tcnative-boringssl-static:2.0.61.Final
//DEPS org.bouncycastle:bcpkix-jdk15on:1.70
//DEPS org.bouncycastle:bcprov-jdk15on:1.70
//DEPS org.slf4j:slf4j-api:1.7.33
//DEPS org.slf4j:slf4j-jdk14:1.7.33
//DEPS io.micrometer:micrometer-core:1.11.0

package org.diennea;

import io.netty.channel.ChannelOption;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollChannelOption;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioChannelOption;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.function.Function;
import javax.net.ssl.SSLException;
import jdk.net.ExtendedSocketOptions;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.server.HttpServer;
import reactor.netty.tcp.SslProvider;

public class Main {

    private static final String COMMON_NAME = "localhost";
    private static final int PORT = 8443;
    private static final String[] TLS_PROTOCOLS = {"TLSv1.3", "TLSv1.2"};
    private static final String KEY_ALGORITHM = "RSA";
    private static final HttpProtocol[] HTTP_PROTOCOLS = {HttpProtocol.HTTP11, HttpProtocol.H2};
    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        final var server = buildHttpServer()
                .handle((request, response) -> response.sendString(Mono.just("Hello world!")))
                .bindNow();
        LOGGER.info("HTTPS server is actively listening on port {}", PORT);
        server.onDispose().block();
    }

    private static HttpServer buildHttpServer() {
        return HttpServer.create()
                .host(COMMON_NAME)
                .port(PORT)
                .protocol(HTTP_PROTOCOLS)
                .secure(Main::buildSslProvider)
                .metrics(true, Function.identity())
                .forwarded((connectionInfo, httpRequest) -> /* dummy forwarded logic */ connectionInfo)
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .runOn(Epoll.isAvailable() ? new EpollEventLoopGroup() : new NioEventLoopGroup())
                .childOption(Epoll.isAvailable()
                        ? EpollChannelOption.TCP_KEEPIDLE
                        : NioChannelOption.of(ExtendedSocketOptions.TCP_KEEPIDLE), 300)
                .childOption(Epoll.isAvailable()
                        ? EpollChannelOption.TCP_KEEPINTVL
                        : NioChannelOption.of(ExtendedSocketOptions.TCP_KEEPINTERVAL), 60)
                .childOption(Epoll.isAvailable()
                        ? EpollChannelOption.TCP_KEEPCNT
                        : NioChannelOption.of(ExtendedSocketOptions.TCP_KEEPCOUNT), 8)
                .maxKeepAliveRequests(1000);
    }

    private static void buildSslProvider(final SslProvider.SslContextSpec sslContextSpec) {
        final var sslContext = createSslContext();
        sslContextSpec.sslContext(sslContext);
    }

    private static SslContext createSslContext() {
        final var keyPair = generateKeyPair();
        LOGGER.info("Public key: {}", keyPair.getPublic());
        LOGGER.info("Private key: {}", keyPair.getPrivate());

        final var certificate = generateSelfSignedCertificate(keyPair);
        LOGGER.info("X509 Certificate: {}", certificate);

        final var sslContextBuilder = SslContextBuilder
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
                ));
        try {
            return sslContextBuilder.build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateKeyPair() {
        try {
            final var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate generateSelfSignedCertificate(final KeyPair keyPair) {
        try {
            final var issuer = new X500Name("CN=" + COMMON_NAME);
            final var serial = BigInteger.valueOf(System.currentTimeMillis());
            final var now = new Date();
            final var validity = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // 1 year
            final var publicKey = keyPair.getPublic();

            final var certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, now, validity, issuer, publicKey);

            final var extUtils = new JcaX509ExtensionUtils();
            final var subjectKeyIdentifier = extUtils.createSubjectKeyIdentifier(publicKey);
            final var subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, COMMON_NAME));
            final var keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            certBuilder
                    .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                    .addExtension(Extension.keyUsage, true, keyUsage)
                    .addExtension(Extension.subjectAlternativeName, false, subjectAltName);

            final var signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (CertificateException | NoSuchAlgorithmException | OperatorCreationException | CertIOException e) {
            throw new RuntimeException(e);
        }
    }
}
