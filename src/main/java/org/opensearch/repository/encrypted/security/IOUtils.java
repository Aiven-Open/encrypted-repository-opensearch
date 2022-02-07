/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

class IOUtils {

    static final int BUFFER_SIZE = 8192; // JDK default buffer size

    static byte[] readAllBytes(final InputStream in) throws IOException {
        int count;
        int totalLength = 0;
        final Queue<byte[]> buffers = new ArrayDeque<>();
        do {
            final byte[] buffer = new byte[BUFFER_SIZE];
            count = in.read(buffer);
            if (count == -1) {
                break;
            }
            if (count < BUFFER_SIZE) {
                buffers.add(Arrays.copyOf(buffer, count));
            } else {
                buffers.add(buffer);
            }
            totalLength += count;
        } while (count > 0);
        return combineBuffers(buffers, totalLength);
    }

    private static byte[] combineBuffers(final Queue<byte[]> buffers, final int totalLength) {
        final byte[] bytes = new byte[totalLength];
        int remaining = totalLength;
        while (remaining > 0) {
            final byte[] buffer = buffers.remove();
            final int copy = Math.min(remaining, buffer.length);
            final int offset = totalLength - remaining;
            System.arraycopy(buffer, 0, bytes, offset, copy);
            remaining -= buffer.length;
        }
        return bytes;
    }

    static byte[] readNBytes(final InputStream in, final int length) throws IOException {
        final byte[] buffer = new byte[length];
        in.read(buffer);
        return buffer;
    }

}
