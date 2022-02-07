/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.opensearch.test.OpenSearchTestCase;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;

public class IOUtilsTests extends OpenSearchTestCase {

    SecureRandom secureRandom = new SecureRandom();

    public void testReadsNBytes() throws IOException {

        final byte[] bytes = new byte[100];
        new SecureRandom().nextBytes(bytes);
        final InputStream in = new ByteArrayInputStream(bytes);

        final byte[] readBytes = IOUtils.readNBytes(in, 10);

        assertEquals(90, in.available());
        assertArrayEquals(Arrays.copyOf(bytes, 10), readBytes);
    }

    public void testReadsAllBytesStreamSmallerThanDefaultBufferSize() throws IOException {
        final byte[] bytes = new byte[100];
        new SecureRandom().nextBytes(bytes);
        final InputStream in = new ByteArrayInputStream(bytes);

        final byte[] readBytes = IOUtils.readAllBytes(in);

        assertEquals(0, in.available());
        assertArrayEquals(bytes, readBytes);
    }

    public void testReadsAllBytesStreamBiggerThanDefaultBufferSize() throws IOException {
        final byte[] bytes = new byte[IOUtils.BUFFER_SIZE * 2];
        new SecureRandom().nextBytes(bytes);
        final InputStream in = new ByteArrayInputStream(bytes);

        final byte[] readBytes = IOUtils.readAllBytes(in);

        assertEquals(0, in.available());
        assertArrayEquals(bytes, readBytes);
    }
}
