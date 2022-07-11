/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensearch.cluster.metadata.RepositoryMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.indices.recovery.RecoverySettings;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.RepositoryPlugin;
import org.opensearch.repositories.Repository;
import org.opensearch.repositories.blobstore.BlobStoreRepository;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import static org.opensearch.repository.encrypted.EncryptedRepositorySettings.REPOSITORY_SETTINGS;
import static org.opensearch.repository.encrypted.EncryptedRepositorySettings.SUPPORTED_STORAGE_TYPES;

public class EncryptedRepositoryPlugin extends Plugin implements RepositoryPlugin {

    private static final Logger LOGGER = LogManager.getLogger(EncryptedRepositoryPlugin.class);

    public static final Setting<String> STORAGE_TYPE_SETTING =
            Setting.simpleString("storage_type", Setting.Property.NodeScope);

    private final EncryptedRepositorySettings encryptedRepositorySettings;

    static {
        try {
            Permissions.doPrivileged(() -> {
                if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
            });
        } catch (IOException e) {
            throw new RuntimeException("Couldn't register BouncyCastle security provider", e);
        }
    }

    public EncryptedRepositoryPlugin(final Settings settings) {
        this.encryptedRepositorySettings = loadSettings(settings);
    }

    private static EncryptedRepositorySettings loadSettings(final Settings settings) {
        try {
            return Permissions.doPrivileged(() -> EncryptedRepositorySettings.load(settings));
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }


    @Override
    public List<Setting<?>> getSettings() {
        return REPOSITORY_SETTINGS;
    }

    @Override
    public Map<String, Repository.Factory> getRepositories(
            final Environment env,
            final NamedXContentRegistry namedXContentRegistry,
            final ClusterService clusterService,
            final RecoverySettings recoverySettings) {

        return Collections.singletonMap(EncryptedRepository.REPOSITORY_TYPE, new Repository.Factory() {
            @Override
            public Repository create(RepositoryMetadata metadata) throws Exception {
                throw new UnsupportedOperationException("Couldn't create a single encrypted repository");
            }

            @Override
            public Repository create(RepositoryMetadata metadata, Function<String, Repository.Factory> typeLookup) throws Exception {
                final BlobStoreRepository storageRepository = createStorageRepository(metadata, typeLookup);
                return new EncryptedRepository(metadata,
                        encryptedRepositorySettings, STORAGE_TYPE_SETTING.get(metadata.settings()), storageRepository,
                        namedXContentRegistry, clusterService, recoverySettings);
            }

            private BlobStoreRepository createStorageRepository(final RepositoryMetadata metadata,
                                                                final Function<String, Repository.Factory> typeLookup)
                    throws Exception {
                if (encryptedRepositorySettings.hasNotSettings()) {
                    throw new SettingsException("Encrypted repository security settings haven't been set");
                }
                if (STORAGE_TYPE_SETTING.exists(metadata.settings()) == false) {
                    throw new SettingsException("Setting "
                            + STORAGE_TYPE_SETTING.getKey()
                            + " hasn't been set. Supported are: " + SUPPORTED_STORAGE_TYPES);
                }
                final String storageType = STORAGE_TYPE_SETTING.get(metadata.settings());
                if (SUPPORTED_STORAGE_TYPES.contains(storageType) == false) {
                    throw new SettingsException("Unsupported storage type "
                            + storageType + " for "
                            + STORAGE_TYPE_SETTING.getKey()
                            + ". Supported are: " + SUPPORTED_STORAGE_TYPES);
                }
                final Repository.Factory storageFactory = typeLookup.apply(storageType);
                if (Objects.isNull(storageFactory)) {
                    throw new IllegalArgumentException("Couldn't create repository type of " + storageType);
                }
                return (BlobStoreRepository)
                        storageFactory.create(new RepositoryMetadata(metadata.name(), storageType, metadata.settings()));
            }

        });

    }

}
