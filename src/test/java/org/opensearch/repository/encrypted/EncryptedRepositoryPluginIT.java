/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoryException;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;

import static org.opensearch.repository.encrypted.RsaKeyAwareTest.readPemContent;
import static org.opensearch.repository.encrypted.RsaKeyAwareTest.writePemFile;

@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class EncryptedRepositoryPluginIT extends OpenSearchIntegTestCase {

	static final Logger LOGGER = LogManager.getLogger(EncryptedRepositoryPluginIT.class);

	static Path publicKeyPem;

	static Path privateKeyPem;

	@BeforeClass
	public static void setupKeys() throws Exception {
		LOGGER.info("Create RSA Keys");
		Permissions.doPrivileged(() -> {
			try {
				Security.addProvider(new BouncyCastleProvider());
				LOGGER.info("Create RSA Keys");
				final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
						BouncyCastleProvider.PROVIDER_NAME);
				keyPairGenerator.initialize(2048, new SecureRandom());
				final KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();
				final Path keysPath = createTempDir("keys-").toAbsolutePath();
				publicKeyPem = keysPath.resolve("test_public.pem");
				privateKeyPem = keysPath.resolve("test_private.pem");

				writePemFile(publicKeyPem, new X509EncodedKeySpec(rsaKeyPair.getPublic().getEncoded()));
				writePemFile(privateKeyPem, new PKCS8EncodedKeySpec(rsaKeyPair.getPrivate().getEncoded()));
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new RuntimeException(e);
			}
		});
	}

	@Override
	protected Collection<Class<? extends Plugin>> nodePlugins() {
		return Collections.singletonList(EncryptedRepositoryPlugin.class);
	}

	@Override
	protected boolean ignoreExternalCluster() {
		return true;
	}

	@Override
	protected Settings nodeSettings(int nodeOrdinal) {
		final Settings.Builder builder = Settings.builder();
		try {
			final MockSecureSettings secureSettings = new MockSecureSettings();

			secureSettings.setFile(
					EncryptedRepositorySettings.FS_PUBLIC_KEY.getConcreteSettingForNamespace("default").getKey(),
					readPemContent(publicKeyPem));
			secureSettings.setFile(
					EncryptedRepositorySettings.FS_PRIVATE_KEY.getConcreteSettingForNamespace("default").getKey(),
					readPemContent(privateKeyPem));
			builder.setSecureSettings(secureSettings);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return builder.put(super.nodeSettings(nodeOrdinal)).build();
	}

	public void testFailsIfNoStorageTypeDefines() throws IOException {
		final RepositoryException exception = expectThrows(RepositoryException.class, () -> client().admin().cluster()
				.preparePutRepository("enc-repo-no-storage-type").setType(EncryptedRepository.REPOSITORY_TYPE).get());
		assertEquals("[enc-repo-no-storage-type] failed to create repository", exception.getMessage());
		assertEquals("Setting storage_type hasn't been set. Supported are: [s3, fs, gcs, azure]",
				exception.getCause().getMessage());
	}

	public void testFailsIfNonExistingStorageType() throws IOException {
		final RepositoryException exception = expectThrows(RepositoryException.class,
				() -> client().admin().cluster().preparePutRepository("enc-repo-wrong-storage-type")
						.setType(EncryptedRepository.REPOSITORY_TYPE)
						.setSettings(Settings.builder().put("storage_type", "aa")).get());
		assertEquals("[enc-repo-wrong-storage-type] failed to create repository", exception.getMessage());
		assertEquals("Unsupported storage type aa for storage_type. Supported are: [s3, fs, gcs, azure]",
				exception.getCause().getMessage());
	}

	public void testCreateRepository() throws IOException {
		assertTrue(client().admin().cluster().preparePutRepository("enc-repo")
				.setType(EncryptedRepository.REPOSITORY_TYPE).setSettings(Settings.builder()
						.put(EncryptedRepositoryPlugin.STORAGE_TYPE_SETTING.getKey(), "fs").put("location", "fs-data"))
				.execute().actionGet().isAcknowledged());
	}

}
