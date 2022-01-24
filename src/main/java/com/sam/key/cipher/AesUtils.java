package com.sam.key.cipher;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AesUtils {

	public static byte[] getRandomNonce(Nonce n) {
		byte[] nonce = new byte[n.getSize()];
		new SecureRandom().nextBytes(nonce);
		return nonce;
	}

	public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, SecureRandom.getInstanceStrong());
		return keyGen.generateKey();
	}

	// AES key derived from a password
	public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		// iterationCount = 200000
		// keyLength = 256
		KeySpec spec = new PBEKeySpec(password, salt, 210_000, 256);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		return secret;
	}

	// hex representation
	public static String hex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}

	// print hex with block size split
	public static String hexWithBlockSize(byte[] bytes, int blockSize) {

		String hex = hex(bytes);

		// one hex = 2 chars
		blockSize = blockSize * 2;

		// better idea how to print this?
		List<String> result = new ArrayList<>();
		int index = 0;
		while (index < hex.length()) {
			result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
			index += blockSize;
		}

		return result.toString();

	}

}
