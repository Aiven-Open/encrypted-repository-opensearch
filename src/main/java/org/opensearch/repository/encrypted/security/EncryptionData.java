/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Objects;

public final class EncryptionData {

	private final SecretKey encryptionKey;

	private final byte[] aad;

	public EncryptionData(final SecretKey encryptionKey, final byte[] aad) {
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
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		final EncryptionData that = (EncryptionData) o;
		return Objects.equals(encryptionKey, that.encryptionKey) && Arrays.equals(aad, that.aad);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(encryptionKey);
		result = 31 * result + Arrays.hashCode(aad);
		return result;
	}
}
