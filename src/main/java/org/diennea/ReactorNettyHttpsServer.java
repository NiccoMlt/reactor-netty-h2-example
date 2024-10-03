package org.diennea;

import io.netty.handler.ssl.SslContext;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import reactor.netty.http.server.HttpServer;

public class ReactorNettyHttpsServer {

    public static void main(String[] args) throws Exception {
        String commonName = "localhost"; // Use appropriate DNS name if needed

        // Generate key pair
        final var keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        final var keyPair = keyPairGenerator.generateKeyPair();

        // Generate self-signed certificate
        X509Certificate cert = SSLCertificateGenerator.generateSelfSignedCertificate(commonName, keyPair);
        PrivateKey privateKey = keyPair.getPrivate(); // Retrieve private key

        // Create SslContext
        SslContext sslContext = NettySslContext.createSslContext(cert, privateKey);

        // Create HTTP/2 server with Reactor Netty, using the generated SslContext
        HttpServer.create()
                .port(8443)
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
                .handle((request, response) -> response
                        .sendString(reactor.core.publisher.Mono.just("Hello over HTTPS with HTTP/2!")))
                .http2Settings(builder -> builder.maxConcurrentStreams(100)) // Enable HTTP/2
                .bindNow() // Bind to port
                .onDispose()
                .block(); // Keep the server running
    }
}
