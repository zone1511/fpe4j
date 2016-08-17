/**
 * Format-Preserving Encryption
 * 
 * Copyright (c) 2016 Weydstone LLC dba Sutton Abinger
 * 
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Sutton Abinger licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.fpe4j;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

/**
 * JUnit test cases for the FF1 class.
 * 
 * @author Kai Johnson
 *
 */
public class FF1Test {

	/**
	 * Test method for {@link org.fpe4j.FF1#FF1(int, int)}.
	 */
	@Test
	public void testFF1() {
		FF1 ff1 = new FF1(10, 0);
		assertNotNull(ff1);
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.FF1#encrypt(SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testEncrypt() throws InvalidKeyException {
		int radix = 8;
		int maxTlen = 16;

		FF1 ff1 = new FF1(radix, maxTlen);
		assertNotNull(ff1);

		// set up generic test inputs
		byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
				(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
				(byte) 0x3C };

		int[] plainText = { 0, 1, 2, 3, 4, 5, 6, 7 };

		// null inputs
		try {
			SecretKeySpec K = null;
			byte[] T = {};
			int[] PT = plainText;
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = null;
			int[] PT = plainText;
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = {};
			int[] PT = null;
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// wrong key type
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = {};
			int[] PT = plainText;
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = plainText;
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = { 1 };
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = new int[Constants.MAXLEN + 1];
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short for radix
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = { 1, 2 };
			ff1.encrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// d > 16
		radix = 128;
		maxTlen = 16;

		ff1 = new FF1(radix, maxTlen);
		assertNotNull(ff1);

		SecretKeySpec K = new SecretKeySpec(key, "AES");
		byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		int[] PT = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
				28, 29, 30, 31, 32 };
		int[] CT = ff1.encrypt(K, T, PT);
		assertArrayEquals(PT, ff1.decrypt(K, T, CT));
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.FF1#decrypt(SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testDecrypt() throws InvalidKeyException {
		int radix = 8;
		int maxTlen = 16;

		FF1 ff1 = new FF1(radix, maxTlen);
		assertNotNull(ff1);

		// set up generic test inputs
		byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
				(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
				(byte) 0x3C };

		int[] cipherText = { 0, 1, 2, 3, 4, 5, 6, 7 };

		// null inputs
		try {
			SecretKeySpec K = null;
			byte[] T = {};
			int[] PT = cipherText;
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = null;
			int[] PT = cipherText;
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = {};
			int[] PT = null;
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// wrong key type
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = {};
			int[] PT = cipherText;
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = cipherText;
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = { 1 };
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = new int[Constants.MAXLEN + 1];
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short for radix
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			int[] PT = { 1, 2 };
			ff1.decrypt(K, T, PT);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// d > 16
		radix = 128;
		maxTlen = 16;

		ff1 = new FF1(radix, maxTlen);
		assertNotNull(ff1);

		SecretKeySpec K = new SecretKeySpec(key, "AES");
		byte[] T = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		int[] CT = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
				28, 29, 30, 31, 32 };
		int[] PT = ff1.decrypt(K, T, CT);
		assertArrayEquals(CT, ff1.encrypt(K, T, PT));
	}

	/**
	 * Stress test for encrypt() and decrypt() methods
	 * <p>
	 * This test exercises the encrypt and decrypt methods with inputs of length
	 * 8, 64, 512 and 4096 symbols with each of the permitted key sizes.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testStress() throws InvalidKeyException {
		int[] keySizes = { 128, 192, 256 };

		FF1 ff1 = new FF1(10, 8);

		// get a new AES key generator
		KeyGenerator keygen;
		try {
			keygen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		// for each key size
		for (int k : keySizes) {
			// generate a new key in the key size
			keygen.init(k);
			SecretKey K = keygen.generateKey();

			// init plaintext to a 1 byte array
			int[] PT = { Math.floorMod(k, 10) };

			// for each plaintext length
			for (int j = 0; j < 4; j++) {

				// make plaintext eight times longer
				PT = Common.concatenate(PT, PT);
				PT = Common.concatenate(PT, PT);
				PT = Common.concatenate(PT, PT);

				// repeat the test four times
				for (int i = 0; i < 4; i++) {
					// create a new tweak array
					byte[] T = Common.bytestring(i, 8);

					// encrypt the plaintext
					int[] CT = ff1.encrypt(K, T, PT);

					// verify decrypted ciphertext against original plaintext
					assertArrayEquals(PT, ff1.decrypt(K, T, CT));

					// use the ciphertext as the new plaintext
					PT = CT;
				}
			}
		}
	}
}
