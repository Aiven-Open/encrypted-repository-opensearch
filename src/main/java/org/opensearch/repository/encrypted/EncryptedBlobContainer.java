/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.opensearch.common.blobstore.BlobContainer;
import org.opensearch.common.blobstore.BlobMetadata;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.common.blobstore.DeleteResult;
import org.opensearch.common.blobstore.support.AbstractBlobContainer;
import org.opensearch.repository.encrypted.security.CryptoIO;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

final class EncryptedBlobContainer extends AbstractBlobContainer {

    private final BlobContainer storageBlobContainer;

    private final CryptoIO cryptoIo;

    EncryptedBlobContainer(final BlobPath path,
                           final CryptoIO cryptoIo,
                           final BlobContainer storageBlobContainer) {
        super(path);
        this.storageBlobContainer = storageBlobContainer;
        this.cryptoIo = cryptoIo;
    }

    @Override
    public boolean blobExists(final String s) throws IOException {
        return storageBlobContainer.blobExists(s);
    }

    @Override
    public InputStream readBlob(final String s) throws IOException {
        return cryptoIo.decrypt(storageBlobContainer.readBlob(s));
    }

    @Override
    public InputStream readBlob(final String path, final long position, final long length) throws IOException {
        throw new UnsupportedOperationException("readBlob hasn't been implemented");
    }

    @Override
    public void writeBlob(final String blobName,
                          final InputStream inputStream,
                          final long blobSize,
                          final boolean failIfAlreadyExists) throws IOException {
        storageBlobContainer.writeBlob(
                blobName,
                cryptoIo.encrypt(inputStream),
                cryptoIo.encryptedStreamSize(blobSize),
                failIfAlreadyExists
        );
    }

    @Override
    public void writeBlobAtomic(final String blobName,
                                final InputStream inputStream,
                                final long blobSize,
                                final boolean failIfAlreadyExists) throws IOException {
        storageBlobContainer.writeBlobAtomic(
                blobName,
                cryptoIo.encrypt(inputStream),
                cryptoIo.encryptedStreamSize(blobSize), failIfAlreadyExists
        );
    }

    @Override
    public DeleteResult delete() throws IOException {
        return storageBlobContainer.delete();
    }

    @Override
    public void deleteBlobsIgnoringIfNotExists(final List<String> list) throws IOException {
        storageBlobContainer.deleteBlobsIgnoringIfNotExists(list);
    }

    @Override
    public Map<String, BlobContainer> children() throws IOException {
        return storageBlobContainer.children();
    }

    @Override
    public Map<String, BlobMetadata> listBlobs() throws IOException {
        return filterOutEncryptionMetadataFile(storageBlobContainer.listBlobs());
    }

    @Override
    public Map<String, BlobMetadata> listBlobsByPrefix(final String prefix) throws IOException {
        return filterOutEncryptionMetadataFile(storageBlobContainer.listBlobsByPrefix(prefix));
    }

    private Map<String, BlobMetadata> filterOutEncryptionMetadataFile(final Map<String, BlobMetadata> blobMetadata) {
        return blobMetadata.entrySet()
                .stream()
                .filter(e -> e.getKey().endsWith(EncryptedRepository.METADATA_FILE_NAME))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

}
