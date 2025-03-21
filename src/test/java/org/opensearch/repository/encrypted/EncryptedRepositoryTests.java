/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.opensearch.cluster.metadata.RepositoryMetadata;
import org.opensearch.cluster.service.ClusterApplierService;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.cache.Cache;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.remote.RemoteStoreEnums;
import org.opensearch.indices.recovery.RecoverySettings;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.repository.encrypted.security.EncryptionData;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_INDEX_SEGMENT_METADATA_RETENTION_MAX_COUNT_SETTING;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_MAX_TRANSLOG_READERS;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_SEGMENT_TRANSFER_TIMEOUT_SETTING;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_STORE_PATH_HASH_ALGORITHM_SETTING;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_STORE_PATH_TYPE_SETTING;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_STORE_TRANSLOG_METADATA;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_TRANSLOG_BUFFER_INTERVAL_SETTING;
import static org.opensearch.indices.RemoteStoreSettings.CLUSTER_REMOTE_TRANSLOG_TRANSFER_TIMEOUT_SETTING;

public class EncryptedRepositoryTests extends OpenSearchTestCase {

	final RepositoryMetadata mockRepositoryMetadata = new RepositoryMetadata("some-repo-metadata", "some-repo-type",
			Settings.builder().build());

	final BlobStoreRepository mockedBlobStoreRepository = mock(BlobStoreRepository.class);

	final NamedXContentRegistry mockedNamedXContentRegistry = mock(NamedXContentRegistry.class);

	final ClusterService mockedClusterService = mock(ClusterService.class);

	final RecoverySettings mockedRecoverySettings = mock(RecoverySettings.class);

	final Cache<String, EncryptionData> mockedCache = (Cache<String, EncryptionData>) mock(Cache.class);

	Settings settings;

	static final Set<Setting<?>> DEFAULT_CLUSTER_SETTINGS_SET = Set.of(CLUSTER_REMOTE_TRANSLOG_BUFFER_INTERVAL_SETTING,
			CLUSTER_REMOTE_INDEX_SEGMENT_METADATA_RETENTION_MAX_COUNT_SETTING,
			CLUSTER_REMOTE_TRANSLOG_TRANSFER_TIMEOUT_SETTING, CLUSTER_REMOTE_STORE_PATH_TYPE_SETTING,
			CLUSTER_REMOTE_STORE_TRANSLOG_METADATA, CLUSTER_REMOTE_STORE_PATH_HASH_ALGORITHM_SETTING,
			CLUSTER_REMOTE_MAX_TRANSLOG_READERS, CLUSTER_REMOTE_SEGMENT_TRANSFER_TIMEOUT_SETTING);

	@Before
	public void setupMocks() throws Exception {
		settings = Settings.builder()
				.put(CLUSTER_REMOTE_TRANSLOG_BUFFER_INTERVAL_SETTING.getKey(),
						IndexSettings.DEFAULT_REMOTE_TRANSLOG_BUFFER_INTERVAL)
				.put(CLUSTER_REMOTE_INDEX_SEGMENT_METADATA_RETENTION_MAX_COUNT_SETTING.getKey(), -1)
				.put(CLUSTER_REMOTE_TRANSLOG_TRANSFER_TIMEOUT_SETTING.getKey(), TimeValue.timeValueSeconds(30))
				.put(CLUSTER_REMOTE_STORE_PATH_TYPE_SETTING.getKey(), RemoteStoreEnums.PathType.FIXED.toString())
				.put(CLUSTER_REMOTE_STORE_TRANSLOG_METADATA.getKey(), true)
				.put(CLUSTER_REMOTE_STORE_PATH_HASH_ALGORITHM_SETTING.getKey(),
						RemoteStoreEnums.PathHashAlgorithm.FNV_1A_COMPOSITE_1.toString())
				.put(CLUSTER_REMOTE_MAX_TRANSLOG_READERS.getKey(), -1)
				.put(CLUSTER_REMOTE_SEGMENT_TRANSFER_TIMEOUT_SETTING.getKey(), TimeValue.timeValueMinutes(30)).build();

		when(mockedClusterService.getClusterApplierService()).thenReturn(mock(ClusterApplierService.class));
		when(mockedClusterService.getSettings()).thenReturn(settings);
		when(mockedClusterService.getClusterSettings())
				.thenReturn(new ClusterSettings(settings, DEFAULT_CLUSTER_SETTINGS_SET));
	}

	public void testBlobStorageLifecycle() throws Exception {
		final EncryptedRepository repository = new EncryptedRepository(mockRepositoryMetadata,
				EncryptedRepositorySettings.load(settings), "fs", mockedBlobStoreRepository,
				mockedNamedXContentRegistry, mockedClusterService, mockedCache, mockedRecoverySettings,
				new BouncyCastleProvider());

		repository.start();
		verify(mockedBlobStoreRepository).start();

		repository.stop();
		verify(mockedBlobStoreRepository).stop();
		verify(mockedCache).invalidateAll();

		reset(mockedCache);

		repository.close();
		verify(mockedBlobStoreRepository).close();
		verify(mockedCache).invalidateAll();

		repository.stats();
		verify(mockedBlobStoreRepository).stats();

	}

}
