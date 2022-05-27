/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Before;
import org.opensearch.common.io.PathUtils;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class RsaKeyAwareTest extends OpenSearchTestCase {

    protected KeyPair rsaKeyPair;

    protected Path publicKeyPem;

    protected Path privateKeyPem;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setupKeys() throws Exception {
        final KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048, new SecureRandom());
        rsaKeyPair = keyPairGenerator.generateKeyPair();

        final Path tmpPath = PathUtils.get(randomFrom(tmpPaths()));
        publicKeyPem = tmpPath.resolve("test_public.pem");
        privateKeyPem = tmpPath.resolve("test_private.pem");

        writePemFile(publicKeyPem, new X509EncodedKeySpec(rsaKeyPair.getPublic().getEncoded()));
        writePemFile(privateKeyPem, new PKCS8EncodedKeySpec(rsaKeyPair.getPrivate().getEncoded()));
    }

    public static void writePemFile(final Path path, final EncodedKeySpec encodedKeySpec) throws IOException {
        try (PemWriter pemWriter = new PemWriter(Files.newBufferedWriter(path))) {
            final PemObject pemObject = new PemObject("SOME KEY", encodedKeySpec.getEncoded());
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
        }
    }

    public static byte[] readPemContent(final Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path)) {
            return in.readAllBytes();
        }
    }

}
