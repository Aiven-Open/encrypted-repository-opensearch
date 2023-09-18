/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.repository.encrypted.security;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.opensearch.common.settings.SettingsException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class RsaKeysReader {

	public static KeyPair readRsaKeyPair(final byte[] publicKeyBytes, final byte[] privateKeyBytes) {
		Objects.requireNonNull(publicKeyBytes, "Pubic key hasn't been set");
		Objects.requireNonNull(privateKeyBytes, "Private key hasn't been set");
		try {
			if (publicKeyBytes.length == 0) {
				throw new SettingsException("Pubic key hasn't been set");
			}
			if (privateKeyBytes.length == 0) {
				throw new SettingsException("Private key hasn't been set");
			}
			final PublicKey publicKey = readPublicKey(publicKeyBytes);
			final PrivateKey privateKey = readPrivateKey(privateKeyBytes);
			return new KeyPair(publicKey, privateKey);
		} catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new SettingsException("Couldn't generate RSA key pair", e);
		}
	}

	private static PublicKey readPublicKey(final byte[] bytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			final byte[] pemContent = readPemContent(bytes);
			final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemContent);
			final KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(keySpec);
		} catch (final IOException e) {
			throw new SettingsException("Couldn't read public key", e);
		}
	}

	private static PrivateKey readPrivateKey(final byte[] bytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			final byte[] pemContent = readPemContent(bytes);
			final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
			final KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(keySpec);
		} catch (final IOException e) {
			throw new SettingsException("Couldn't read private key", e);
		}
	}

	private static byte[] readPemContent(final byte[] bytes) throws IOException {
		final InputStreamReader reader = new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8);
		try (PemReader pemReader = new PemReader(reader)) {
			final PemObject pemObject = pemReader.readPemObject();
			if (Objects.isNull(pemObject)) {
				throw new SettingsException("Couldn't read PEM");
			}
			return pemObject.getContent();
		}
	}

}
