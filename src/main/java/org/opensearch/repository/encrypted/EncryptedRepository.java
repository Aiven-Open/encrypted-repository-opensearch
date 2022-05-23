/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.RepositoryMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.blobstore.BlobContainer;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.common.blobstore.BlobStore;
import org.opensearch.common.bytes.BytesArray;
import org.opensearch.common.cache.Cache;
import org.opensearch.common.cache.CacheBuilder;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.ByteSizeUnit;
import org.opensearch.common.unit.ByteSizeValue;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.indices.recovery.RecoverySettings;
import org.opensearch.repositories.RepositoryException;
import org.opensearch.repositories.RepositoryStats;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.repository.encrypted.security.CryptoIO;
import org.opensearch.repository.encrypted.security.EncryptionData;
import org.opensearch.repository.encrypted.security.EncryptionDataGenerator;
import org.opensearch.repository.encrypted.security.EncryptionDataSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;

public class EncryptedRepository extends BlobStoreRepository {

    private static final Logger LOGGER = LogManager.getLogger(EncryptedRepository.class);

    public static final String REPOSITORY_TYPE = "encrypted";

    public static final String METADATA_FILE_NAME = ".repository_metadata";

    public static final Setting<String> CLIENT_SETTING =
            Setting.simpleString("client", "default");

    public static final Setting<Boolean> COMPRESS_SETTING =
            Setting.boolSetting("compress", true);

    public static final Setting<ByteSizeValue> CHUNK_SIZE_SETTING = Setting.byteSizeSetting(
            "chunk_size",
            new ByteSizeValue(1, ByteSizeUnit.GB),
            new ByteSizeValue(500, ByteSizeUnit.MB),
            new ByteSizeValue(64, ByteSizeUnit.GB)
    );

    private final String blobStorageRepositoryType;

    private final BlobStoreRepository blobStorageRepository;

    private final EncryptedRepositorySettings encryptedRepositorySettings;

    private final Cache<String, EncryptionData> encryptionDataCache;

    private final EncryptionDataGenerator encryptionDataGenerator;

    public EncryptedRepository(final RepositoryMetadata metadata,
                               final EncryptedRepositorySettings encryptedRepositorySettings,
                               final String blobStorageRepositoryType,
                               final BlobStoreRepository blobStorageRepository,
                               final NamedXContentRegistry namedXContentRegistry,
                               final ClusterService clusterService,
                               final RecoverySettings recoverySettings) {
        this(metadata, encryptedRepositorySettings,
                blobStorageRepositoryType, blobStorageRepository,
                namedXContentRegistry, clusterService,
                CacheBuilder.<String, EncryptionData>builder().build(),
                recoverySettings);
    }

    public EncryptedRepository(final RepositoryMetadata metadata,
                               final EncryptedRepositorySettings encryptedRepositorySettings,
                               final String blobStorageRepositoryType,
                               final BlobStoreRepository blobStorageRepository,
                               final NamedXContentRegistry namedXContentRegistry,
                               final ClusterService clusterService,
                               final Cache<String, EncryptionData> encryptionDataCache,
                               final RecoverySettings recoverySettings) {
        super(metadata, COMPRESS_SETTING.get(metadata.settings()),
                namedXContentRegistry, clusterService, recoverySettings);
        this.encryptedRepositorySettings = encryptedRepositorySettings;
        this.blobStorageRepositoryType = blobStorageRepositoryType;
        this.blobStorageRepository = blobStorageRepository;
        this.encryptionDataCache = encryptionDataCache;
        this.encryptionDataGenerator = new EncryptionDataGenerator();
    }

    @Override
    public RepositoryStats stats() {
        return blobStorageRepository.stats();
    }

    @Override
    public BlobPath basePath() {
        return blobStorageRepository.basePath();
    }

    @Override
    protected ByteSizeValue chunkSize() {
        return CHUNK_SIZE_SETTING.get(metadata.settings());
    }

    @Override
    protected void doStart() {
        blobStorageRepository.start();
        super.doStart();
    }

    @Override
    protected void doStop() {
        super.doStop();
        encryptionDataCache.invalidateAll();
        blobStorageRepository.stop();
    }

    @Override
    protected void doClose() {
        super.doClose();
        encryptionDataCache.invalidateAll();
        blobStorageRepository.close();
    }

    @Override
    protected BlobStore createBlobStore() throws Exception {
        return new EncryptedBlobStore(
                blobStorageRepository.blobStore(),
                new CryptoIO(
                        encryptionDataCache.computeIfAbsent(
                                settingsKey(metadata.settings()),
                                this::createOrRestoreEncryptionData)
                )
        );
    }

    private String settingsKey(final Settings settings) {
        return String.format(
                Locale.getDefault(),
                "%s-%s",
                blobStorageRepositoryType,
                CLIENT_SETTING.get(settings)
        );
    }

    private EncryptionData createOrRestoreEncryptionData(final String clientName) throws IOException {
        final BlobStore blobStore = blobStorageRepository.blobStore();
        final BlobContainer blobContainer = blobStore.blobContainer(basePath());
        final EncryptionData encryptionData;
        final EncryptionDataSerializer encryptionDataSerializer =
                new EncryptionDataSerializer(encryptedRepositorySettings.rsaKeyPair(clientName));
        if (blobContainer.blobExists(METADATA_FILE_NAME)) {
            LOGGER.info("Restore encryption data");
            try (InputStream in = blobContainer.readBlob(METADATA_FILE_NAME)) {
                encryptionData = encryptionDataSerializer.deserialize(IOUtils.readAllBytes(in));
            }
        } else {
            LOGGER.info("Create encryption data");
            if (isReadOnly()) {
                throw new RepositoryException(
                        REPOSITORY_TYPE,
                        "Couldn't create encryption data. The repository " + metadata.name() + " is in readonly mode"
                );
            }
            encryptionData = encryptionDataGenerator.generate();
            final byte[] bytes = encryptionDataSerializer.serialize(encryptionData);
            try (InputStream in = new BytesArray(bytes).streamInput()) {
                blobContainer.writeBlobAtomic(METADATA_FILE_NAME, in, bytes.length, true);
            }
        }
        return encryptionData;
    }

}
