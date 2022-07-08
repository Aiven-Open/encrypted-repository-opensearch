/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.util.set.Sets;
import org.opensearch.repository.encrypted.security.RsaKeysReader;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

class EncryptedRepositorySettings {

    private static final Logger LOGGER = LogManager.getLogger(EncryptedRepositorySettings.class);

    public static final String PREFIX = "encrypted.";

    public static final String AZURE_PREFIX = PREFIX + "azure.";

    public static final String FS_PREFIX = PREFIX + "fs.";

    public static final String GCS_PREFIX = PREFIX + "gcs.";

    public static final String S3_PREFIX = PREFIX + "s3.";

    public static final Setting<String> SECURITY_PROVIDER =
            Setting.simpleString("encrypted.security_provider", "", Setting.Property.NodeScope);

    public static final Set<String> SUPPORTED_STORAGE_TYPES = Sets.newHashSet("fs", "azure", "gcs", "s3");

    public static final Setting.AffixSetting<InputStream> AZURE_PRIVATE_KEY =
            Setting.affixKeySetting(
                        AZURE_PREFIX, "private_key",
                        key -> SecureSetting.secureFile(key, null)
            );

    public static final Setting.AffixSetting<InputStream> AZURE_PUBLIC_KEY =
            Setting.affixKeySetting(
                    AZURE_PREFIX, "public_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    public static final Setting.AffixSetting<InputStream> FS_PRIVATE_KEY =
            Setting.affixKeySetting(
                    FS_PREFIX, "private_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    public static final Setting.AffixSetting<InputStream> FS_PUBLIC_KEY =
            Setting.affixKeySetting(
                    FS_PREFIX, "public_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    public static final Setting.AffixSetting<InputStream> GCS_PRIVATE_KEY =
            Setting.affixKeySetting(
                    GCS_PREFIX, "private_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    public static final Setting.AffixSetting<InputStream> GCS_PUBLIC_KEY =
            Setting.affixKeySetting(
                    GCS_PREFIX, "public_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    private static final Setting.AffixSetting<InputStream> S3_PRIVATE_KEY =
            Setting.affixKeySetting(
                    S3_PREFIX, "private_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    private static final Setting.AffixSetting<InputStream> S3_PUBLIC_KEY =
            Setting.affixKeySetting(
                    S3_PREFIX, "public_key",
                    key -> SecureSetting.secureFile(key, null)
            );

    public static final List<Setting<?>> REPOSITORY_SETTINGS =
            Collections.unmodifiableList(
                    Arrays.asList(
                            SECURITY_PROVIDER,
                            AZURE_PUBLIC_KEY, AZURE_PRIVATE_KEY,
                            FS_PUBLIC_KEY, FS_PRIVATE_KEY,
                            GCS_PUBLIC_KEY, GCS_PRIVATE_KEY,
                            S3_PUBLIC_KEY, S3_PRIVATE_KEY)
            );

    private static final Map<String, Tuple<Setting.AffixSetting<InputStream>, Setting.AffixSetting<InputStream>>>
            PREFIXES = new HashMap<String, Tuple<Setting.AffixSetting<InputStream>, Setting.AffixSetting<InputStream>>>() {
        {
            put(AZURE_PREFIX, Tuple.tuple(AZURE_PRIVATE_KEY, AZURE_PUBLIC_KEY));
            put(FS_PREFIX, Tuple.tuple(FS_PRIVATE_KEY, FS_PUBLIC_KEY));
            put(GCS_PREFIX, Tuple.tuple(GCS_PRIVATE_KEY, GCS_PUBLIC_KEY));
            put(S3_PREFIX, Tuple.tuple(S3_PRIVATE_KEY, S3_PUBLIC_KEY));
        }
    };

    private final Map<String, KeyPair> rsaKeyPairs;

    private final String encryptionProviderName;

    EncryptedRepositorySettings(final String encryptionProviderName, final Map<String, KeyPair> rsaKeyPairs) {
        this.encryptionProviderName = encryptionProviderName;
        this.rsaKeyPairs = rsaKeyPairs;
    }

    public String encryptionProviderName() {
        return encryptionProviderName;
    }

    public KeyPair rsaKeyPair(final String clientName) {
        return rsaKeyPairs.get(clientName);
    }

    public boolean hasNotSettings() {
        return rsaKeyPairs.isEmpty();
    }

    public static EncryptedRepositorySettings load(final Settings settings) throws IOException {
        final Map<String, KeyPair> repoSettings = new HashMap<>();
        for (final Map.Entry<String, Tuple<Setting.AffixSetting<InputStream>, Setting.AffixSetting<InputStream>>>
                prefix : PREFIXES.entrySet()) {
            final String storagePrefix = prefix.getKey();
            final String storageType = storagePrefix.substring(PREFIX.length(), storagePrefix.length() - 1);
            final Set<String> clients = settings.getGroups(storagePrefix).keySet();
            for (final String client : clients) {
                final String repoSettingsKey =
                        String.format(Locale.getDefault(), "%s-%s", storageType, client);
                repoSettings.put(repoSettingsKey, createKeyPair(client, prefix.getValue(), settings));
            }
        }
        final String encryptionProviderName = resolveEncryptionProviderName(settings);
        return new EncryptedRepositorySettings(encryptionProviderName, Collections.unmodifiableMap(repoSettings));
    }

    private static String resolveEncryptionProviderName(final Settings settings) {
        String encryptionProviderName = BouncyCastleProvider.PROVIDER_NAME;
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (SECURITY_PROVIDER.exists(settings)) {
            final String securityProviderClass = SECURITY_PROVIDER.get(settings);
            try {
                final Class<?> providerClass = Class.forName(securityProviderClass);
                final Provider provider = (Provider) providerClass.getConstructor().newInstance();
                if (Security.getProvider(provider.getName()) != null) {
                    LOGGER.info("Add {}", securityProviderClass);
                    Security.addProvider(provider);
                }
                encryptionProviderName = provider.getName();
            } catch (ClassNotFoundException | NoSuchMethodException
                     | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                throw new SettingsException("Couldn't create security provider " + securityProviderClass, e);
            }
        }
        return encryptionProviderName;
    }

    private static KeyPair createKeyPair(final String prefix,
                                         final Tuple<Setting.AffixSetting<InputStream>, Setting.AffixSetting<InputStream>> keySettings,
                                         final Settings settings) throws IOException {
        LOGGER.info("Load key pair for: {}", prefix);
        try (InputStream privateKeyIn = getConfigValue(keySettings.v1(), prefix, settings);
             InputStream publicKeyIn = getConfigValue(keySettings.v2(), prefix, settings)) {
            final byte[] publicKey = publicKeyIn.readAllBytes();
            final byte[] privateKey = privateKeyIn.readAllBytes();
            return RsaKeysReader.readRsaKeyPair(publicKey, privateKey);
        }
    }

    private static <T> T getConfigValue(final Setting.AffixSetting<T> setting,
                                        final String prefix,
                                        final Settings settings) {
        final Setting<T> concreteSetting = setting.getConcreteSettingForNamespace(prefix);
        if (concreteSetting.exists(settings) == false) {
            throw new SettingsException("Setting " + concreteSetting.getKey() + " hasn't been set");
        }
        return concreteSetting.get(settings);
    }

}
