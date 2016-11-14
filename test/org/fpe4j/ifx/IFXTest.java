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
package org.fpe4j.ifx;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.fpe4j.utilities.Utilities;
import org.junit.Test;

/**
 * JUnit test cases for the IFX class
 * 
 * @author Kai Johnson
 *
 */
public class IFXTest {

	/**
	 * Test method for {@link org.fpe4j.ifx.IFX#IFX(int[])}.
	 */
	@Test
	public void testIFX() {

		// null
		try {
			new IFX(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			new IFX(new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one element
		try {
			int[] W = { 256 };
			new IFX(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// negative elements
		try {
			int[] W = { 7, -8, 9 };
			new IFX(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// elements too small
		try {
			int[] W = { 5, 5 };
			new IFX(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// elements too large
		try {
			int[] W = { 256, 65536, 128 };
			new IFX(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// several elements
		int[] W1 = { 10, 26, 26, 26, 10, 10, 10 };
		IFX ifx = new IFX(W1);
		assertEquals(0, ifx.getU().compareTo(BigInteger.valueOf(10985)));
		assertEquals(0, ifx.getV().compareTo(BigInteger.valueOf(16000)));
		assertEquals(0, ifx.getW().compareTo(Functions.product(W1)));
		assertEquals(0, ifx.getW().compareTo(ifx.getU().multiply(ifx.getV())));

		// fuzz
		Random random = new Random();
		for (int i = 0; i < 100; i++) {
			int[] W = new int[10];
			for (int j = 0; j < 10; j++) {
				W[j] = random.nextInt(65534) + 2;
			}
			ifx = new IFX(W);
			assertEquals(0, ifx.getW().compareTo(Functions.product(W)));
			assertEquals(0, ifx.getW().compareTo(ifx.getU().multiply(ifx.getV())));
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.IFX#num(int[])}.
	 */
	@Test
	public void testNum() {
		int[] W = { 10, 26, 26, 26, 10, 10, 10 };
		IFX ifx = new IFX(W);

		// null
		try {
			ifx.num(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			ifx.num(new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// wrong length
		try {
			int[] X = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
			ifx.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			int[] X = { 6, 5, 4, 3, 2, 1 };
			ifx.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// negative elements
		try {
			int[] X = { 4, 3, 2, 1, 0, -1, -2 };
			ifx.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// elements out of range
		try {
			int[] X = { 9, 10, 11, 12, 13, 14, 15 };
			ifx.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		int[] X1 = { 0, 0, 0, 0, 0, 0, 0 };
		BigInteger x1 = ifx.num(X1);
		assertEquals(0, x1.compareTo(BigInteger.valueOf(0)));

		// one
		int[] X2 = { 0, 0, 0, 0, 0, 0, 1 };
		BigInteger x2 = ifx.num(X2);
		assertEquals(0, x2.compareTo(BigInteger.valueOf(1)));

		// maximum
		int[] X3 = { 9, 25, 25, 25, 9, 9, 9 };
		BigInteger x3 = ifx.num(X3);
		assertEquals(0, x3.compareTo(BigInteger.valueOf(175759999)));

		// fuzz
		Random random = new Random();
		for (int i = 0; i < 100; i++) {
			int[] W4 = new int[10];
			int[] X4 = new int[10];
			int[] X5 = new int[10];
			for (int j = 0; j < 10; j++) {
				W4[j] = random.nextInt(65534) + 2;
				X4[j] = W4[j] - 1;
				X5[j] = random.nextInt(W4[j]);
			}
			ifx = new IFX(W4);
			assertEquals(0, ifx.num(X4).compareTo(ifx.getW().subtract(BigInteger.ONE)));
			assertArrayEquals(X5, ifx.str(ifx.num(X5)));
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.IFX#str(java.math.BigInteger)}.
	 */
	@Test
	public void testStr() {
		int[] W = { 10, 26, 26, 26, 10, 10, 10 };
		IFX ifx = new IFX(W);

		// null
		try {
			ifx.str(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// negative
		try {
			ifx.str(BigInteger.ONE.negate());
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// out of range
		try {
			ifx.str(ifx.getW());
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		int[] X1 = { 0, 0, 0, 0, 0, 0, 0 };
		BigInteger x1 = BigInteger.valueOf(0);
		assertArrayEquals(X1, ifx.str(x1));

		// one
		int[] X2 = { 0, 0, 0, 0, 0, 0, 1 };
		BigInteger x2 = BigInteger.valueOf(1);
		assertArrayEquals(X2, ifx.str(x2));

		// maximum
		int[] X3 = { 9, 25, 25, 25, 9, 9, 9 };
		BigInteger x3 = BigInteger.valueOf(175759999);
		assertArrayEquals(X3, ifx.str(x3));

		// fuzz
		Random random = new Random();
		for (int i = 0; i < 100; i++) {
			int[] W4 = new int[10];
			int[] X4 = new int[10];
			int[] X5 = new int[10];
			for (int j = 0; j < 10; j++) {
				W4[j] = random.nextInt(65534) + 2;
				X4[j] = W4[j] - 1;
				X5[j] = random.nextInt(W4[j]);
			}
			ifx = new IFX(W4);
			assertArrayEquals(X4, ifx.str(ifx.getW().subtract(BigInteger.ONE)));
			assertArrayEquals(X5, ifx.str(ifx.num(X5)));
		}
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.ifx.IFX#encrypt(javax.crypto.SecretKey, byte[], int[])}.
	 */
	@Test
	public void testEncrypt() {
		int[] W = { 10, 26, 26, 26, 10, 10, 10 };
		IFX ifx = new IFX(W);

		// K is null
		try {
			SecretKeySpec K = null;
			byte[] T = {};
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// K is invalid
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = {};
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is null
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = null;
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is null
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] X = null;
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] X = { 0, 1, 2, 3, 4, 5 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] X = { 0, 1, 2, 3, 4, 5, 6, 7 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X contains negative values
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] X = { 0, 1, 2, 3, -4, 5, 6 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X contains values out of range
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] X = { 0, 1, 2, 33, 4, 5, 6 };
			ifx.encrypt(K, T, X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// T is empty
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			int[] Y = { 7, 0, 3, 13, 6, 6, 8 };
			assertArrayEquals(Y, ifx.encrypt(K, T, X));
		} catch (InvalidKeyException e) {
			fail();
		}

		// T is set
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = Utilities.hexStringToByteArray("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			int[] Y = { 4, 3, 2, 15, 5, 8, 4 };
			assertArrayEquals(Y, ifx.encrypt(K, T, X));
		} catch (InvalidKeyException e) {
			fail();
		}
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.ifx.IFX#decrypt(javax.crypto.SecretKey, byte[], int[])}.
	 */
	@Test
	public void testDecrypt() {
		int[] W = { 10, 26, 26, 26, 10, 10, 10 };
		IFX ifx = new IFX(W);

		// K is null
		try {
			SecretKeySpec K = null;
			byte[] T = {};
			int[] Y = { 0, 1, 2, 3, 4, 5, 6 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// K is invalid
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = {};
			int[] Y = { 0, 1, 2, 3, 4, 5, 6 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is null
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = null;
			int[] Y = { 0, 1, 2, 3, 4, 5, 6 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// Y is null
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] Y = null;
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// Y is too short
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] Y = { 0, 1, 2, 3, 4, 5 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// Y is too long
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] Y = { 0, 1, 2, 3, 4, 5, 6, 7 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// Y contains negative values
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] Y = { 0, 1, 2, 3, -4, 5, 6 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// Y contains values out of range
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] Y = { 0, 1, 2, 33, 4, 5, 6 };
			ifx.decrypt(K, T, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// T is empty
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = {};
			int[] Y = { 7, 0, 3, 13, 6, 6, 8 };
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			assertArrayEquals(X, ifx.decrypt(K, T, Y));
		} catch (InvalidKeyException e) {
			fail();
		}

		// T is set
		try {
			SecretKeySpec K = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
					"AES");
			byte[] T = Utilities.hexStringToByteArray("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
			int[] Y = { 4, 3, 2, 15, 5, 8, 4 };
			int[] X = { 0, 1, 2, 3, 4, 5, 6 };
			assertArrayEquals(X, ifx.decrypt(K, T, Y));
		} catch (InvalidKeyException e) {
			fail();
		}
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.ifx.IFX#decrypt(javax.crypto.SecretKey, byte[], int[])}
	 * and
	 * {@link org.fpe4j.ifx.IFX#encrypt(javax.crypto.SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             if there is a programming error in the test case
	 */
	@Test
	public void testStress() throws InvalidKeyException {
		int[] keySizes = { 128, 192, 256 };
		int[] textSizes = { 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233 };

		// get a new AES key generator
		KeyGenerator keygen;
		try {
			keygen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		// get a new random number generator
		Random random = new Random();

		// for each key size
		for (int k : keySizes) {
			// generate a new key in the key size
			keygen.init(k);
			SecretKey K = keygen.generateKey();

			// for each plaintext length
			for (int j : textSizes) {
				// generate radices and values
				int[] W = new int[j];
				int[] X = new int[j];
				do {
					for (int i = 0; i < j; i++) {
						W[i] = random.nextInt(65534) + 2;
						X[i] = random.nextInt(W[i]);
					}
					// make sure product(W) >= 100
				} while (Functions.product(W).compareTo(BigInteger.valueOf(100)) <= 0);

				// repeat the test four times
				for (int i = 0; i < 4; i++) {
					// create a new tweak array
					byte[] T = new byte[i * 8];
					random.nextBytes(T);

					// create an ifx instance
					IFX ifx = new IFX(W);

					// encrypt the plaintext
					int[] CT = ifx.encrypt(K, T, X);

					// decrypt the ciphertext
					int[] PT = ifx.decrypt(K, T, CT);

					// verify decrypted ciphertext against original plaintext
					assertArrayEquals(X, PT);

					// use the ciphertext as the new plaintext
					X = CT;
				}
			}
		}
	}
}
