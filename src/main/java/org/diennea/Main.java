package org.diennea;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.bouncycastle.operator.OperatorCreationException;

public class Main {
    public static final String HOST = "localhost";
    public static final int PORT = 8080;

    public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        /* final var httpServer = HttpServer.create()
                .host(HOST)
                .port(PORT)
                .protocol(HTTP11, H2)
                .secure(sslContextSpec ->)
                .compress(true);
        httpServer.warmup().block();
        final var listeningChannel = httpServer.bindNow(); */
    }
}
