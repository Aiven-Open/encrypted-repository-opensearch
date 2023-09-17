/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted;

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EncryptedRepositorySettingsTests extends RsaKeyAwareTest {

	public void testReadDefaultSettings() throws Exception {
		final MockSecureSettings secureSettings = new MockSecureSettings();
		secureSettings.setFile("encrypted.s3.default.private_key", readPemContent(privateKeyPem));
		secureSettings.setFile("encrypted.s3.default.public_key", readPemContent(publicKeyPem));
		final EncryptedRepositorySettings encryptedRepositorySettings = EncryptedRepositorySettings
				.load(Settings.builder().setSecureSettings(secureSettings).build());

		assertEquals(rsaKeyPair.getPublic(), encryptedRepositorySettings.rsaKeyPair("s3-default").getPublic());
		assertEquals(rsaKeyPair.getPrivate(), encryptedRepositorySettings.rsaKeyPair("s3-default").getPrivate());
	}

	public void testReadClientSettings() throws Exception {
		final KeyPairGenerator clientKeyPairGenerator = KeyPairGenerator.getInstance("RSA");

		final KeyPair client1KeyPair = clientKeyPairGenerator.generateKeyPair();
		final KeyPair client2KeyPair = clientKeyPairGenerator.generateKeyPair();

		final Tuple<Path, Path> client1PemFiles = writePemFilesFor("client1", client1KeyPair);
		final Tuple<Path, Path> client2PemFiles = writePemFilesFor("client2", client2KeyPair);

		final MockSecureSettings secureSettings = new MockSecureSettings();
		secureSettings.setFile("encrypted.fs.default.private_key", readPemContent(privateKeyPem));
		secureSettings.setFile("encrypted.fs.default.public_key", readPemContent(publicKeyPem));
		secureSettings.setFile("encrypted.s3.client1.private_key", readPemContent(client1PemFiles.v2()));
		secureSettings.setFile("encrypted.s3.client1.public_key", readPemContent(client1PemFiles.v1()));
		secureSettings.setFile("encrypted.azure.client2.private_key", readPemContent(client2PemFiles.v2()));
		secureSettings.setFile("encrypted.azure.client2.public_key", readPemContent(client2PemFiles.v1()));
		final EncryptedRepositorySettings encryptedRepositorySettings = EncryptedRepositorySettings
				.load(Settings.builder().setSecureSettings(secureSettings).build());

		assertEquals(rsaKeyPair.getPublic(), encryptedRepositorySettings.rsaKeyPair("fs-default").getPublic());
		assertEquals(rsaKeyPair.getPrivate(), encryptedRepositorySettings.rsaKeyPair("fs-default").getPrivate());
		assertEquals(client1KeyPair.getPublic(), encryptedRepositorySettings.rsaKeyPair("s3-client1").getPublic());
		assertEquals(client1KeyPair.getPrivate(), encryptedRepositorySettings.rsaKeyPair("s3-client1").getPrivate());
		assertEquals(client2KeyPair.getPublic(), encryptedRepositorySettings.rsaKeyPair("azure-client2").getPublic());
		assertEquals(client2KeyPair.getPrivate(), encryptedRepositorySettings.rsaKeyPair("azure-client2").getPrivate());
	}

	public void testThrowsSettingsExceptionForNoKeySettings() throws IOException {
		Throwable t = assertThrows(SettingsException.class, () -> EncryptedRepositorySettings
				.load(Settings.builder().put("encrypted.gcs.default.value", "key_value").build()));
		assertEquals("Setting encrypted.gcs.default.private_key hasn't been set", t.getMessage());

		final MockSecureSettings noPublicKeySecureSettings = new MockSecureSettings();
		noPublicKeySecureSettings.setFile("encrypted.gcs.default.private_key", readPemContent(privateKeyPem));
		t = assertThrows(SettingsException.class, () -> EncryptedRepositorySettings
				.load(Settings.builder().setSecureSettings(noPublicKeySecureSettings).build()));
		assertEquals("Setting encrypted.gcs.default.public_key hasn't been set", t.getMessage());

		final MockSecureSettings noPrivateKeySecureSettings = new MockSecureSettings();
		noPrivateKeySecureSettings.setFile("encrypted.gcs.default.public_key", readPemContent(publicKeyPem));
		t = assertThrows(SettingsException.class, () -> EncryptedRepositorySettings
				.load(Settings.builder().setSecureSettings(noPrivateKeySecureSettings).build()));
		assertEquals("Setting encrypted.gcs.default.private_key hasn't been set", t.getMessage());

		final MockSecureSettings noPrivateKeyClient1SecureSettings = new MockSecureSettings();
		noPrivateKeyClient1SecureSettings.setFile("encrypted.azure.default.public_key", readPemContent(publicKeyPem));
		noPrivateKeyClient1SecureSettings.setFile("encrypted.azure.default.private_key", readPemContent(privateKeyPem));
		noPrivateKeyClient1SecureSettings.setFile("encrypted.fs.client1.public_key", readPemContent(publicKeyPem));
		t = assertThrows(SettingsException.class, () -> EncryptedRepositorySettings
				.load(Settings.builder().setSecureSettings(noPrivateKeyClient1SecureSettings).build()));
		assertEquals("Setting encrypted.fs.client1.private_key hasn't been set", t.getMessage());

	}

	private Tuple<Path, Path> writePemFilesFor(final String clientName, final KeyPair clientKeyPair)
			throws IOException {
		final Path tmpPath = PathUtils.get(randomFrom(tmpPaths()));
		final Path publicKeyPemPath = tmpPath.resolve(clientName + "_public_key.pem");
		final Path privateKeyPemPath = tmpPath.resolve(clientName + "_private_key.pem");
		writePemFile(publicKeyPemPath, new X509EncodedKeySpec(clientKeyPair.getPublic().getEncoded()));
		writePemFile(privateKeyPemPath, new PKCS8EncodedKeySpec(clientKeyPair.getPrivate().getEncoded()));
		return Tuple.tuple(publicKeyPemPath, privateKeyPemPath);
	}

}