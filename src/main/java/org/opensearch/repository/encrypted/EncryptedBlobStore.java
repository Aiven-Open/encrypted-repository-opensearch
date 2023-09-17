/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.opensearch.common.blobstore.BlobContainer;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.common.blobstore.BlobStore;
import org.opensearch.repository.encrypted.security.CryptoIO;

import java.io.IOException;
import java.util.Map;

final class EncryptedBlobStore implements BlobStore {

	private final BlobPath storageBasePath;

	private final BlobStore storageBlobStore;

	private final CryptoIO cryptoIo;

	EncryptedBlobStore(final BlobStore storageBlobStore, final CryptoIO cryptoIo) {
		this.storageBasePath = BlobPath.cleanPath();
		this.storageBlobStore = storageBlobStore;
		this.cryptoIo = cryptoIo;
	}

	@Override
	public BlobContainer blobContainer(final BlobPath blobPath) {
		BlobPath storageBlobContainerPath = storageBasePath;
		for (final String s : blobPath) {
			storageBlobContainerPath = storageBlobContainerPath.add(s);
		}
		final BlobContainer storageBlobContainer = storageBlobStore.blobContainer(storageBlobContainerPath);
		return new EncryptedBlobContainer(blobPath, cryptoIo, storageBlobContainer);
	}

	@Override
	public void close() throws IOException {
	}

	@Override
	public Map<String, Long> stats() {
		return storageBlobStore.stats();
	}

}
