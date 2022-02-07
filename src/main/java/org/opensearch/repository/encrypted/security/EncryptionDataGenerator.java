/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

@FunctionalInterface
public interface EncryptionDataGenerator {

    int KEY_SIZE = 256;

    int ADD_SIZE = 32;

    final class EncryptionData {

        private final SecretKey encryptionKey;

        private final byte[] aad;

        EncryptionData(final SecretKey encryptionKey, final byte[] aad) {
            this.encryptionKey = encryptionKey;
            this.aad = aad;
        }

        public SecretKey encryptionKey() {
            return encryptionKey;
        }

        public byte[] aad() {
            return aad;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            final EncryptionDataGenerator.EncryptionData that = (EncryptionData) o;
            return Objects.equals(encryptionKey, that.encryptionKey) && Arrays.equals(aad, that.aad);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(encryptionKey);
            result = 31 * result + Arrays.hashCode(aad);
            return result;
        }
    }

    EncryptionData generate();

    EncryptionDataGenerator DEFAULT_GENERATOR = () -> {
        try {
            final KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");
            aesKeyGenerator.init(KEY_SIZE, new SecureRandom());
            final SecureRandom random = new SecureRandom();
            final byte[] aad = new byte[ADD_SIZE];
            random.nextBytes(aad);
            return new EncryptionDataGenerator.EncryptionData(aesKeyGenerator.generateKey(), aad);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("Couldn't create encrypt key provider", e);
        }
    };

}
