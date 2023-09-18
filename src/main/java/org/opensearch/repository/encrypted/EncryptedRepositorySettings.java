/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.repository.encrypted.security.RsaKeysReader;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class EncryptedRepositorySettings {

	private static final Logger LOGGER = LogManager.getLogger(EncryptedRepositorySettings.class);

	public static final String PREFIX = "encrypted.";

	public static final String AZURE_PREFIX = PREFIX + "azure.";

	public static final String FS_PREFIX = PREFIX + "fs.";

	public static final String GCS_PREFIX = PREFIX + "gcs.";

	public static final String S3_PREFIX = PREFIX + "s3.";

	public static final List<String> SUPPORTED_STORAGE_TYPES = List.of("azure", "fs", "gcs", "s3");

	public static final Setting.AffixSetting<InputStream> AZURE_PRIVATE_KEY = Setting.affixKeySetting(AZURE_PREFIX,
			"private_key", key -> SecureSetting.secureFile(key, null));

	public static final Setting.AffixSetting<InputStream> AZURE_PUBLIC_KEY = Setting.affixKeySetting(AZURE_PREFIX,
			"public_key", key -> SecureSetting.secureFile(key, null));

	public static final Setting.AffixSetting<InputStream> FS_PRIVATE_KEY = Setting.affixKeySetting(FS_PREFIX,
			"private_key", key -> SecureSetting.secureFile(key, null));

	public static final Setting.AffixSetting<InputStream> FS_PUBLIC_KEY = Setting.affixKeySetting(FS_PREFIX,
			"public_key", key -> SecureSetting.secureFile(key, null));

	public static final Setting.AffixSetting<InputStream> GCS_PRIVATE_KEY = Setting.affixKeySetting(GCS_PREFIX,
			"private_key", key -> SecureSetting.secureFile(key, null));

	public static final Setting.AffixSetting<InputStream> GCS_PUBLIC_KEY = Setting.affixKeySetting(GCS_PREFIX,
			"public_key", key -> SecureSetting.secureFile(key, null));

	private static final Setting.AffixSetting<InputStream> S3_PRIVATE_KEY = Setting.affixKeySetting(S3_PREFIX,
			"private_key", key -> SecureSetting.secureFile(key, null));

	private static final Setting.AffixSetting<InputStream> S3_PUBLIC_KEY = Setting.affixKeySetting(S3_PREFIX,
			"public_key", key -> SecureSetting.secureFile(key, null));

	public static final List<Setting<?>> REPOSITORY_SETTINGS = List.of(AZURE_PUBLIC_KEY, AZURE_PRIVATE_KEY,
			FS_PUBLIC_KEY, FS_PRIVATE_KEY, GCS_PUBLIC_KEY, GCS_PRIVATE_KEY, S3_PUBLIC_KEY, S3_PRIVATE_KEY);

	private static final Map<String, Tuple<Setting.AffixSetting<InputStream>, Setting.AffixSetting<InputStream>>> PREFIXES = new HashMap<>() {
		{
			put(AZURE_PREFIX, Tuple.tuple(AZURE_PRIVATE_KEY, AZURE_PUBLIC_KEY));
			put(FS_PREFIX, Tuple.tuple(FS_PRIVATE_KEY, FS_PUBLIC_KEY));
			put(GCS_PREFIX, Tuple.tuple(GCS_PRIVATE_KEY, GCS_PUBLIC_KEY));
			put(S3_PREFIX, Tuple.tuple(S3_PRIVATE_KEY, S3_PUBLIC_KEY));
		}
	};

	private final Map<String, KeyPair> rsaKeyPairs;

	EncryptedRepositorySettings(final Map<String, KeyPair> rsaKeyPairs) {
		this.rsaKeyPairs = rsaKeyPairs;
	}

	public KeyPair rsaKeyPair(final String clientName) {
		return rsaKeyPairs.get(clientName);
	}

	public boolean hasNotSettings() {
		return rsaKeyPairs.isEmpty();
	}

	public static EncryptedRepositorySettings load(final Settings settings) throws IOException {
		final Map<String, KeyPair> repoSettings = new HashMap<>();
		for (final Map.Entry<String, Tuple<Setting.AffixSetting<InputStream>, Setting.AffixSetting<InputStream>>> prefix : PREFIXES
				.entrySet()) {
			final String storagePrefix = prefix.getKey();
			final String storageType = storagePrefix.substring(PREFIX.length(), storagePrefix.length() - 1);
			final Set<String> clients = settings.getGroups(storagePrefix).keySet();
			for (final String client : clients) {
				final String repoSettingsKey = String.format(Locale.getDefault(), "%s-%s", storageType, client);
				repoSettings.put(repoSettingsKey, createKeyPair(client, prefix.getValue(), settings));
			}
		}
		return new EncryptedRepositorySettings(Map.copyOf(repoSettings));
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

	private static <T> T getConfigValue(final Setting.AffixSetting<T> setting, final String prefix,
			final Settings settings) {
		final Setting<T> concreteSetting = setting.getConcreteSettingForNamespace(prefix);
		if (!concreteSetting.exists(settings)) {
			throw new SettingsException("Setting " + concreteSetting.getKey() + " hasn't been set");
		}
		return concreteSetting.get(settings);
	}

}
