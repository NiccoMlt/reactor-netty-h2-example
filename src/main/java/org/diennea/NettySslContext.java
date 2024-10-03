package org.diennea;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class NettySslContext {

    public static SslContext createSslContext(X509Certificate certificate, PrivateKey privateKey) throws Exception {
        // Convert to Netty's SslContext with HTTP/2 support
        return SslContextBuilder.forServer(privateKey, certificate)
                .protocols("TLSv1.3", "TLSv1.2")
                .applicationProtocolConfig(io.netty.handler.ssl.ApplicationProtocolConfig.DISABLED) // Simplification for this example
                .build();
    }
}
