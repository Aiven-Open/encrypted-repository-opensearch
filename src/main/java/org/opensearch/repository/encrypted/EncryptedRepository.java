/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.opensearch.cluster.metadata.RepositoryMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.common.blobstore.BlobStore;
import org.opensearch.common.cache.Cache;
import org.opensearch.common.cache.CacheBuilder;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.unit.ByteSizeUnit;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.indices.recovery.RecoverySettings;
import org.opensearch.repositories.RepositoryStats;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.repository.encrypted.security.CryptoIO;
import org.opensearch.repository.encrypted.security.EncryptionData;
import org.opensearch.repository.encrypted.security.EncryptionDataSerializer;

import java.security.Provider;
import java.util.Locale;

public class EncryptedRepository extends BlobStoreRepository {

	public static final String REPOSITORY_TYPE = "encrypted";

	public static final Setting<String> CLIENT_SETTING = Setting.simpleString("client", "default");

	public static final Setting<Boolean> COMPRESS_SETTING = Setting.boolSetting("compress", true);

	public static final Setting<ByteSizeValue> CHUNK_SIZE_SETTING = Setting.byteSizeSetting("chunk_size",
			new ByteSizeValue(1, ByteSizeUnit.GB), new ByteSizeValue(500, ByteSizeUnit.MB),
			new ByteSizeValue(64, ByteSizeUnit.GB));

	private final String blobStorageRepositoryType;

	private final BlobStoreRepository blobStorageRepository;

	private final EncryptedRepositorySettings encryptedRepositorySettings;

	private final Cache<String, EncryptionData> encryptionDataCache;

	private final Provider securityProvider;

	public EncryptedRepository(final RepositoryMetadata metadata,
			final EncryptedRepositorySettings encryptedRepositorySettings, final String blobStorageRepositoryType,
			final BlobStoreRepository blobStorageRepository, final NamedXContentRegistry namedXContentRegistry,
			final ClusterService clusterService, final RecoverySettings recoverySettings,
			final Provider securityProvider) {
		this(metadata, encryptedRepositorySettings, blobStorageRepositoryType, blobStorageRepository,
				namedXContentRegistry, clusterService, CacheBuilder.<String, EncryptionData>builder().build(),
				recoverySettings, securityProvider);
	}

	public EncryptedRepository(final RepositoryMetadata metadata,
			final EncryptedRepositorySettings encryptedRepositorySettings, final String blobStorageRepositoryType,
			final BlobStoreRepository blobStorageRepository, final NamedXContentRegistry namedXContentRegistry,
			final ClusterService clusterService, final Cache<String, EncryptionData> encryptionDataCache,
			final RecoverySettings recoverySettings, final Provider securityProvider) {
		super(metadata, namedXContentRegistry, clusterService, recoverySettings);
		this.encryptedRepositorySettings = encryptedRepositorySettings;
		this.blobStorageRepositoryType = blobStorageRepositoryType;
		this.blobStorageRepository = blobStorageRepository;
		this.encryptionDataCache = encryptionDataCache;
		this.securityProvider = securityProvider;
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
		return new EncryptedBlobStore(blobStorageRepository.blobStore(),
				new CryptoIO(new EncryptionDataSerializer(
						encryptedRepositorySettings.rsaKeyPair(settingsKey(metadata.settings())), securityProvider),
						securityProvider));
	}

	private String settingsKey(final Settings settings) {
		return String.format(Locale.getDefault(), "%s-%s", blobStorageRepositoryType, CLIENT_SETTING.get(settings));
	}

}
