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

	private final byte[] iv;

	public EncryptionData(final SecretKey encryptionKey, final byte[] aad, final byte[] iv) {
		this.encryptionKey = encryptionKey;
		this.aad = aad;
		this.iv = iv;
	}

	public SecretKey encryptionKey() {
		return encryptionKey;
	}

	public byte[] aad() {
		return aad;
	}

	public byte[] iv() {
		return iv;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		EncryptionData that = (EncryptionData) o;
		return Objects.equals(encryptionKey, that.encryptionKey) && Arrays.equals(aad, that.aad)
				&& Arrays.equals(iv, that.iv);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(encryptionKey);
		result = 31 * result + Arrays.hashCode(aad);
		result = 31 * result + Arrays.hashCode(iv);
		return result;
	}
}
