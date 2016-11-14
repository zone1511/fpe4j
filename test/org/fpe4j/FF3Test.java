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

import static org.fpe4j.Common.floor;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

/**
 * JUnit test cases for the FF3 class.
 * 
 * @author Kai Johnson
 *
 */
public class FF3Test {

	/**
	 * Test method for {@link org.fpe4j.FF3#FF3(int)}.
	 */
	@Test
	public void testFF3() {
		FF3 ff3 = new FF3(10);
		assertNotNull(ff3);

		// check values of minlen and maxlen
		int[] radixValues = { 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
		int[] expectedMinlen = { 7, 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
		int[] expectedMaxlen = { 192, 96, 64, 48, 38, 32, 26, 24, 20, 18, 16, 16, 14, 12, 12, 12 };

		for (int i = 0; i < radixValues.length; i++) {
			try {
				ff3 = new FF3(radixValues[i]);
			} catch (IllegalArgumentException e) {
				// shouldn't happen unless the values of Constants.MINRADIX and
				// Constants.MAXRADIX have changed, and if they have we'll skip
				// this radix value
				continue;
			}

			int minlen = ff3.getMinlen();
			int maxlen = ff3.getMaxlen();

			assertTrue(2 <= minlen);
			assertTrue(minlen <= maxlen);
			assertTrue(maxlen <= 2 * floor(Math.log(Math.pow(2, 96)) / Math.log(radixValues[i])));
			assertEquals(expectedMinlen[i], minlen);
			assertEquals(expectedMaxlen[i], maxlen);
		}

		// radix too small
		try {
			new FF3(Constants.MINRADIX - 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix too big
		try {
			new FF3(Constants.MAXRADIX + 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.FF3#encrypt(SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testEncrypt() throws InvalidKeyException {
		int radix = 8;

		FF3 ff3 = new FF3(radix);
		assertNotNull(ff3);

		// set up generic test inputs
		byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
				(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
				(byte) 0x3C };

		int[] plainText = { 0, 1, 2, 3, 4, 5, 6, 7 };

		// null inputs
		try {
			SecretKeySpec K = null;
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] PT = plainText;
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = null;
			int[] PT = plainText;
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] PT = null;
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// wrong key type
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] PT = plainText;
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// wrong key format
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecretKey K = keygen.generateKey();
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] PT = plainText;
			ff3.encrypt(K, T, PT);
			/*
			 * Actually, the KeyGenerator creates a key in RAW format, so we
			 * don't throw an exception here. It would be nice to test with a
			 * key in ASN.1 format.
			 */
			// fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6 };
			int[] PT = plainText;
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// T is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
			int[] PT = plainText;
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] PT = new int[ff3.getMinlen() - 1];
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] PT = new int[ff3.getMaxlen() + 1];
			ff3.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// encrypt
		SecretKeySpec K = new SecretKeySpec(key, "AES");
		byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
		int[] PT = new int[ff3.getMinlen()];
		int[] CT = ff3.encrypt(K, T, PT);
		assertArrayEquals(PT, ff3.decrypt(K, T, CT));
		PT = new int[ff3.getMaxlen()];
		CT = ff3.encrypt(K, T, PT);
		assertArrayEquals(PT, ff3.decrypt(K, T, CT));

	}

	/**
	 * Test method for {@link org.fpe4j.FF3#decrypt(SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testDecrypt() throws InvalidKeyException {
		int radix = 8;

		FF3 ff3 = new FF3(radix);
		assertNotNull(ff3);

		// set up generic test inputs
		byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
				(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
				(byte) 0x3C };

		int[] cipherText = { 0, 1, 2, 3, 4, 5, 6, 7 };

		// null inputs
		try {
			SecretKeySpec K = null;
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] CT = cipherText;
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = null;
			int[] CT = cipherText;
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] CT = null;
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// wrong key type
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] CT = cipherText;
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// wrong key format
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecretKey K = keygen.generateKey();
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] CT = cipherText;
			ff3.decrypt(K, T, CT);
			// fail();
			/*
			 * Actually, the KeyGenerator creates a key in RAW format, so we
			 * don't throw an exception here. It would be nice to test with a
			 * key in ASN.1 format.
			 */
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6 };
			int[] CT = cipherText;
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// T is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
			int[] CT = cipherText;
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] CT = new int[ff3.getMinlen() - 1];
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
			int[] CT = new int[ff3.getMaxlen() + 1];
			ff3.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// decrypt
		SecretKeySpec K = new SecretKeySpec(key, "AES");
		byte[] T = { 0, 1, 2, 3, 4, 5, 6, 7 };
		int[] CT = new int[ff3.getMinlen()];
		int[] PT = ff3.decrypt(K, T, CT);
		assertArrayEquals(CT, ff3.encrypt(K, T, PT));
		CT = new int[ff3.getMaxlen()];
		PT = ff3.decrypt(K, T, CT);
		assertArrayEquals(CT, ff3.encrypt(K, T, PT));
	}

	/**
	 * Stress test for encrypt() and decrypt() methods.
	 * 
	 * This test exercises the encrypt and decrypt methods with radix values
	 * from {@value org.fpe4j.Constants#MINRADIX} to
	 * {@value org.fpe4j.Constants#MAXRADIX} with each of the permitted input
	 * lengths and key sizes.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testStress() throws InvalidKeyException {
		int[] keySizes = { 128, 192, 256 };

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

			// for each radix power of 2
			for (int j = Constants.MINRADIX; j <= Constants.MAXRADIX; j *= 2) {

				FF3 ff3 = new FF3(j);

				// for each permitted plaintext length
				for (int i = ff3.getMinlen(); i <= ff3.getMaxlen(); i++) {

					int[] PT = new int[i];

					// create a new tweak array
					byte[] T = Common.bytestring(i, 8);

					// encrypt the plaintext
					int[] CT = ff3.encrypt(K, T, PT);

					// verify decrypted ciphertext against original plaintext
					assertArrayEquals(PT, ff3.decrypt(K, T, CT));

					// use the ciphertext as the new plaintext
					PT = CT;
				}
			}
		}
	}
}
