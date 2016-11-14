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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.fpe4j.FFX.ArithmeticFunction;
import org.fpe4j.FFX.FeistelMethod;
import org.fpe4j.FFX.RoundCounter;
import org.fpe4j.FFX.RoundFunction;
import org.fpe4j.FFX.SplitFunction;
import org.fpe4j.utilities.Utilities;
import org.junit.Test;

/**
 * JUnit test cases for the A10Parameters class.
 * 
 * @author Kai Johnson
 *
 */
public class A10Test {

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#A10Parameters()}
	 */
	@Test
	public void testA10Parameters() {
		A10Parameters result = new A10Parameters();
		assertNotNull(result);
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getRadix()}
	 */
	@Test
	public void testGetRadix() {
		A10Parameters a10Parameters = new A10Parameters();
		assertEquals(10, a10Parameters.getRadix());
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getMinLen()}
	 */
	@Test
	public void testGetMinLen() {
		A10Parameters a10Parameters = new A10Parameters();
		assertEquals(4, a10Parameters.getMinLen());
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getMaxLen()}
	 */
	@Test
	public void testGetMaxLen() {
		A10Parameters a10Parameters = new A10Parameters();
		assertEquals(36, a10Parameters.getMaxLen());
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getMinTLen()}
	 */
	@Test
	public void testGetMinTLen() {
		A10Parameters a10Parameters = new A10Parameters();
		assertEquals(0, a10Parameters.getMinTLen());
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getMaxTLen()}
	 */
	@Test
	public void testGetMaxTLen() {
		A10Parameters a10Parameters = new A10Parameters();
		assertEquals(Integer.MAX_VALUE, a10Parameters.getMaxTLen());
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getArithmeticFunction()}
	 */
	@Test
	public void testGetArithmeticFunction() {
		A10Parameters a10Parameters = new A10Parameters();
		ArithmeticFunction arithmeticFunction = a10Parameters.getArithmeticFunction();

		int[] a = { 0, 1, 2, 3 };
		int[] b = { 6, 7, 8, 9 };
		int[] ab = { 6, 9, 1, 2 };

		assertArrayEquals(ab, arithmeticFunction.add(a, b));
		assertArrayEquals(b, arithmeticFunction.subtract(ab, a));
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getFeistelMethod()}
	 */
	@Test
	public void testGetFeistelMethod() {
		A10Parameters a10Parameters = new A10Parameters();
		assertEquals(FeistelMethod.TWO, a10Parameters.getFeistelMethod());
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getSplitter()}
	 */
	@Test
	public void testGetSplitter() {
		A10Parameters a10Parameters = new A10Parameters();
		SplitFunction splitter = a10Parameters.getSplitter();

		assertEquals(4, splitter.split(8));
		assertEquals(4, splitter.split(9));
		assertEquals(63, splitter.split(127));
		assertEquals(64, splitter.split(128));
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getRoundCounter()}
	 */
	@Test
	public void testGetRoundCounter() {
		A10Parameters a10Parameters = new A10Parameters();
		RoundCounter roundCounter = a10Parameters.getRoundCounter();

		try {
			roundCounter.rnds(37);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		assertEquals(12, roundCounter.rnds(36));
		assertEquals(12, roundCounter.rnds(10));
		assertEquals(18, roundCounter.rnds(9));
		assertEquals(18, roundCounter.rnds(6));
		assertEquals(24, roundCounter.rnds(5));
		assertEquals(24, roundCounter.rnds(4));
		try {
			roundCounter.rnds(3);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.A10Parameters#getRoundFunction()}
	 */
	@Test
	public void testGetRoundFunction() {
		A10Parameters a10Parameters = new A10Parameters();
		RoundFunction roundFunction = a10Parameters.getRoundFunction();

		// create an AES key from the key data
		SecretKeySpec K1 = new SecretKeySpec(Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"), "AES");
		assertTrue(roundFunction.validKey(K1));

		// null key
		SecretKeySpec K2 = null;
		assertFalse(roundFunction.validKey(K2));

		// DES key
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K3 = keygen.generateKey();
			assertFalse(roundFunction.validKey(K3));
		} catch (Exception e) {
			fail(e.toString());
		}

		/*
		 * test roundFunction.F(SecretKey K, int n, byte[] T, int i, int[] B) in
		 * testStress()
		 */
	}

	/**
	 * Stress test for {@link org.fpe4j.FFX#encrypt(SecretKey, byte[], int[])}
	 * and {@link org.fpe4j.FFX#decrypt(SecretKey, byte[], int[])} methods using
	 * A10Parameters.
	 * <p>
	 * This test exercises A10 encryption and decryption with inputs of length
	 * 8, 9, 10, 13, 14, 19, 20, 31, 32, and 128 symbols with each of the
	 * permitted key sizes.
	 * 
	 * @throws InvalidKeyException
	 *             Only if there's a programming error in the test case.
	 */
	@Test
	public void testStress() throws InvalidKeyException {
		int[] keySizes = { 128, 192, 256 };
		int[] textSizes = { 4, 5, 9, 10, 36 };

		// create an A10 instance of FFX
		A10Parameters params = new A10Parameters();
		FFX ffx = new FFX(params);
		assertNotNull(ffx);

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

			// for each plaintext length
			for (int j : textSizes) {

				// random number in the range 0 .. 2^j
				byte[] bytes = new byte[Common.ceiling(j / 8.0)];
				new Random().nextBytes(bytes);
				BigInteger x = new BigInteger(bytes).mod(BigInteger.valueOf(params.getRadix()).pow(j));

				// initialize plaintext of length j
				int[] PT = Common.str(x, params.getRadix(), j);

				// repeat the test four times
				for (int i = 0; i < 4; i++) {
					// create a new tweak array
					byte[] T = Common.bytestring(i, 8);

					// encrypt the plaintext
					int[] CT = ffx.encrypt(K, T, PT);

					// verify decrypted ciphertext against original plaintext
					assertArrayEquals(PT, ffx.decrypt(K, T, CT));

					// use the ciphertext as the new plaintext
					PT = CT;
				}
			}
		}
	}
}
