/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public interface Decryptor {

    default Cipher createDecryptingCipher(final Key key,
                                          final String transformation) {
        return createDecryptingCipher(key, null, transformation);
    }

    default Cipher createDecryptingCipher(final Key key,
                                          final AlgorithmParameterSpec params,
                                          final String transformation) {
        Objects.requireNonNull(key, "key hasn't been set");
        Objects.requireNonNull(transformation, "transformation hasn't been set");
        try {
            final Cipher cipher = Cipher.getInstance(transformation);
            if (Objects.nonNull(params)) {
                cipher.init(
                        Cipher.DECRYPT_MODE,
                        key,
                        params,
                        new SecureRandom());
            } else {
                cipher.init(
                        Cipher.DECRYPT_MODE,
                        key,
                        new SecureRandom());
            }
            return cipher;
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Couldn't create decrypt cipher", e);
        }
    }
}
