/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.junit.Before;
import org.opensearch.cluster.metadata.RepositoryMetadata;
import org.opensearch.cluster.service.ClusterApplierService;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.cache.Cache;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.indices.recovery.RecoverySettings;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.repository.encrypted.security.EncryptionData;
import org.opensearch.test.OpenSearchTestCase;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class EncryptedRepositoryTests extends OpenSearchTestCase {

    final RepositoryMetadata mockRepositoryMetadata =
            new RepositoryMetadata("some-repo-metadata", "some-repo-type", Settings.builder().build());

    final BlobStoreRepository mockedBlobStoreRepository = mock(BlobStoreRepository.class);

    final NamedXContentRegistry mockedNamedXContentRegistry = mock(NamedXContentRegistry.class);

    final ClusterService mockedClusterService = mock(ClusterService.class);

    final RecoverySettings mockedRecoverySettings = mock(RecoverySettings.class);

    final Cache<String, EncryptionData> mockedCache =
            (Cache<String, EncryptionData>) mock(Cache.class);

    @Before
    public void setupMocks() throws Exception {
        when(mockedClusterService.getClusterApplierService()).thenReturn(mock(ClusterApplierService.class));
    }

    public void testBlobStorageLifecycle() throws Exception {
        final EncryptedRepository repository =
                new EncryptedRepository(
                        mockRepositoryMetadata,
                        EncryptedRepositorySettings.load(Settings.EMPTY),
                        "fs",
                        mockedBlobStoreRepository,
                        mockedNamedXContentRegistry,
                        mockedClusterService,
                        mockedCache,
                        mockedRecoverySettings);

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
