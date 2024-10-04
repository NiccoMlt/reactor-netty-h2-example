/// usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS io.projectreactor.netty:reactor-netty-core:1.1.7
//DEPS io.projectreactor.netty:reactor-netty-http:1.1.7
//DEPS io.netty:netty-tcnative-boringssl-static:2.0.61.Final
//DEPS org.bouncycastle:bcpkix-jdk15on:1.70
//DEPS org.bouncycastle:bcprov-jdk15on:1.70
//DEPS org.slf4j:slf4j-api:1.7.33
//DEPS org.slf4j:slf4j-jdk14:1.7.33
//DEPS io.micrometer:micrometer-core:1.11.0

package org.diennea;

import static reactor.netty.ConnectionObserver.State.CONNECTED;
import static reactor.netty.NettyPipeline.H2OrHttp11Codec;
import static reactor.netty.NettyPipeline.HttpTrafficHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollChannelOption;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioChannelOption;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.OpenSslCachingX509KeyManagerFactory;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.IdleStateHandler;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
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
    private static final Class<SslHandler> SSL_HANDLER_TYPE = io.netty.handler.ssl.SslHandler.class;
    private static final String SSL_HANDLER_NAME = "reactor.left.sslHandler";

    public static void main(String[] args) {
        final var httpServer = buildHttpServer();
        httpServer.warmup().block();
        LOGGER.info("HTTPS server is actively listening on port {}", PORT);
        httpServer.bindNow();
    }

    private static HttpServer buildHttpServer() {
        final var epollAvailable = Epoll.isAvailable();
        LOGGER.info("Epoll is available? {}", epollAvailable);
        return HttpServer.create()
                .host(COMMON_NAME)
                .port(PORT)
                .protocol(HTTP_PROTOCOLS)
                .secure(Main::buildSslProvider)
                .metrics(true, Function.identity())
                .forwarded((connectionInfo, httpRequest) -> /* dummy forwarded logic */ connectionInfo)
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .runOn(epollAvailable ? new EpollEventLoopGroup() : new NioEventLoopGroup())
                .childOption(epollAvailable
                        ? EpollChannelOption.TCP_KEEPIDLE
                        : NioChannelOption.of(ExtendedSocketOptions.TCP_KEEPIDLE), 300)
                .childOption(epollAvailable
                        ? EpollChannelOption.TCP_KEEPINTVL
                        : NioChannelOption.of(ExtendedSocketOptions.TCP_KEEPINTERVAL), 60)
                .childOption(epollAvailable
                        ? EpollChannelOption.TCP_KEEPCNT
                        : NioChannelOption.of(ExtendedSocketOptions.TCP_KEEPCOUNT), 8)
                .maxKeepAliveRequests(1000)
                .doOnChannelInit((observer, channel, remoteAddress) -> {
                    // Clients Idle Timeout in seconds
                    final var handler = new IdleStateHandler(0, 0, 120);
                    final var pipeline = channel.pipeline();
                    pipeline.addFirst("idleStateHandler", handler);

                    // todo add OCSP stapling

                    LOGGER.info("Pipeline: {}", pipeline.names());
                    // LOGGER.info("Pipeline: {}", channel.pipeline().toString());
                    LOGGER.info("Pipeline contains SSLHandler? {}", pipeline.get(SSL_HANDLER_TYPE) != null);
                    LOGGER.info("Pipeline['reactor.left.sslHandler']: {}", pipeline.get(SSL_HANDLER_NAME));
                })
                .doOnConnection(conn -> {
                    LOGGER.info("New connection!");
                    conn.channel().closeFuture().addListener(e -> LOGGER.info("Connection closed!"));
                    // config.getGroup().add(conn.channel());
                })
                .childObserve((connection, state) -> {
                    final var handler = new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
                            if (msg instanceof final HttpRequest request) {
                                request.setUri(request.uri()
                                        .replaceAll("\\[", "%5B")
                                        .replaceAll("]", "%5D")
                                );
                            }
                            ctx.fireChannelRead(msg);
                        }
                    };
                    final var channel = connection.channel();
                    if (state == CONNECTED) {
                        if (channel.pipeline().get(HttpTrafficHandler) != null) {
                            channel.pipeline().addBefore(HttpTrafficHandler, "uriEncoder", handler);
                        }
                        if (channel.pipeline().get(H2OrHttp11Codec) != null) {
                            channel.pipeline().addAfter(H2OrHttp11Codec, "uriEncoder", handler);
                        }
                        LOGGER.debug("Unsupported pipeline structure: {}; skipping...", channel.pipeline().toString());
                    }
                })
                .httpRequestDecoder(option -> option.maxHeaderSize(8192))
                .handle((request, response) -> response.sendString(Mono.just("Hello world!")))
                .compress(0);
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

        final var keyStore = persistKeyStore(keyPair, certificate);
        final var keyFactory = buildKeyFactory(keyStore);
        final var trustManager = buildTrustManager(keyStore);

        final var sslContextBuilder = SslContextBuilder
                .forServer(keyFactory)
                .trustManager(trustManager)
                .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL)
                .protocols(TLS_PROTOCOLS)
                .enableOcsp(true)
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
            LOGGER.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private static TrustManagerFactory buildTrustManager(final KeyStore keyStore) {
        try {
            final var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            return trustManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            LOGGER.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateKeyPair() {
        try {
            final var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage(), e);
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
            LOGGER.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private static KeyStore persistKeyStore(final KeyPair keyPair, final X509Certificate certificate) {
        try {
            final var keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            keyStore.setKeyEntry("selfsigned", keyPair.getPrivate(), "password".toCharArray(), new java.security.cert.Certificate[]{certificate});
            try (FileOutputStream fos = new FileOutputStream("keystore.jks")) {
                keyStore.store(fos, "password".toCharArray());
            }
            return keyStore;
        } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException e) {
            LOGGER.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private static KeyManagerFactory buildKeyFactory(final KeyStore keyStore) {
        try {
            final var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            final var wrapper = new OpenSslCachingX509KeyManagerFactory(keyManagerFactory);
            wrapper.init(keyStore, "password".toCharArray());
            return wrapper;
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }
}
