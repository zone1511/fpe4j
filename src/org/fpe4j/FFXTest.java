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
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.fpe4j.FFX.ArithmeticFunction;
import org.fpe4j.FFX.FFXParameters;
import org.fpe4j.FFX.FeistelMethod;
import org.fpe4j.FFX.RoundCounter;
import org.fpe4j.FFX.RoundFunction;
import org.fpe4j.FFX.SplitFunction;
import org.junit.Test;

/**
 * JUnit test cases for the FFX class.
 * 
 * @author Kai Johnson
 *
 */
public class FFXTest {

	/**
	 * Template class for FFX test parameters.
	 * 
	 * @author Kai Johnson
	 *
	 */
	private class FFXTestParameters implements FFXParameters {

		int radix;
		int minlen;
		int maxlen;
		int minTlen;
		int maxTlen;
		ArithmeticFunction arithmeticFunction;
		FeistelMethod feistelMethod;
		SplitFunction splitFunction;
		RoundCounter roundCounter;
		RoundFunction roundFunction;

		@Override
		public int getRadix() {
			return radix;
		}

		@Override
		public int getMinLen() {
			return minlen;
		}

		@Override
		public int getMaxLen() {
			return maxlen;
		}

		@Override
		public int getMinTLen() {
			return minTlen;
		}

		@Override
		public int getMaxTLen() {
			return maxTlen;
		}

		@Override
		public ArithmeticFunction getArithmeticFunction() {
			return arithmeticFunction;
		}

		@Override
		public FeistelMethod getFeistelMethod() {
			return feistelMethod;
		}

		@Override
		public SplitFunction getSplitter() {
			return splitFunction;
		}

		@Override
		public RoundCounter getRoundCounter() {
			return roundCounter;
		}

		@Override
		public RoundFunction getRoundFunction() {
			return roundFunction;
		}
	}

	/**
	 * Split function for FFX tests.
	 */
	private FFX.SplitFunction splitFunction1 = new FFX.SplitFunction() {

		@Override
		public int split(int n) {
			return n / 2;
		}
	};

	/**
	 * Round counter function that returns a sufficient number of rounds.
	 */
	private FFX.RoundCounter roundCounter1 = new FFX.RoundCounter() {

		@Override
		public int rnds(int n) {
			return 10;
		}
	};

	/**
	 * Round counter function that returns an insufficient number of rounds.
	 */
	private FFX.RoundCounter roundCounter2 = new FFX.RoundCounter() {

		@Override
		public int rnds(int n) {
			return 7;
		}
	};

	/**
	 * Simple unciphered round function for FFX tests.
	 */
	private FFX.RoundFunction roundFunction1 = new FFX.RoundFunction() {

		@Override
		public boolean validKey(SecretKey K) {
			// validate K
			if (K == null)
				return false;
			if (!K.getAlgorithm().equals("AES"))
				return false;
			if (!K.getFormat().equals("RAW"))
				return false;

			return true;
		}

		@Override
		public int[] F(SecretKey K, int n, byte[] T, int i, int[] B) throws InvalidKeyException {
			int[] Y = new int[n - B.length];
			Arrays.fill(Y, 1);
			return Y;
		}
	};

	/**
	 * Test method for
	 * {@link org.fpe4j.FFX#getBlockwiseArithmeticFunction(int)}.
	 */
	@Test
	public void testGetBlockwiseArithmeticFunction() {
		// radix is too small
		try {
			FFX.getBlockwiseArithmeticFunction(Constants.MINRADIX - 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		ArithmeticFunction arithmeticFunction = FFX.getBlockwiseArithmeticFunction(10);

		// X is null
		try {
			arithmeticFunction.add(null, new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			arithmeticFunction.subtract(null, new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is empty
		try {
			arithmeticFunction.add(new int[0], new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			arithmeticFunction.subtract(new int[0], new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// Y is null
		try {
			arithmeticFunction.add(new int[5], null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			arithmeticFunction.subtract(new int[5], null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// Y is empty
		try {
			arithmeticFunction.add(new int[5], new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			arithmeticFunction.subtract(new int[5], new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X.length != Y.length
		try {
			arithmeticFunction.add(new int[5], new int[4]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			arithmeticFunction.subtract(new int[5], new int[4]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		int[] X = { 8, 8, 8, 8, 8 };
		int[] Y = { 2, 2, 2, 2, 2 };

		// addition with overflow
		int[] Z1 = { 1, 1, 1, 1, 0 };
		assertArrayEquals(Z1, arithmeticFunction.add(X, Y));

		// subtraction
		int[] Z2 = { 6, 6, 6, 6, 6 };
		assertArrayEquals(Z2, arithmeticFunction.subtract(X, Y));

		// subtraction with underflow
		int[] Z3 = { 3, 3, 3, 3, 4 };
		assertArrayEquals(Z3, arithmeticFunction.subtract(Y, X));

		// addition
		int[] Z4 = { 4, 4, 4, 4, 4 };
		assertArrayEquals(Z4, arithmeticFunction.add(Y, Y));
	}

	/**
	 * Test method for {@link org.fpe4j.FFX#getCharwiseArithmeticFunction(int)}.
	 */
	@Test
	public void testGetCharwiseArithmeticFunction() {
		// radix is too small
		try {
			FFX.getCharwiseArithmeticFunction(Constants.MINRADIX - 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		ArithmeticFunction arithmeticFunction = FFX.getCharwiseArithmeticFunction(10);

		// X is null
		try {
			arithmeticFunction.add(null, new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			arithmeticFunction.subtract(null, new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is empty
		try {
			arithmeticFunction.add(new int[0], new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			arithmeticFunction.subtract(new int[0], new int[5]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// Y is null
		try {
			arithmeticFunction.add(new int[5], null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			arithmeticFunction.subtract(new int[5], null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// Y is empty
		try {
			arithmeticFunction.add(new int[5], new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			arithmeticFunction.subtract(new int[5], new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X.length != Y.length
		try {
			arithmeticFunction.add(new int[5], new int[4]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			arithmeticFunction.subtract(new int[5], new int[4]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		int[] X = { 8, 8, 8, 8, 8 };
		int[] Y = { 2, 2, 2, 2, 2 };

		// addition with overflow
		int[] Z1 = { 0, 0, 0, 0, 0 };
		assertArrayEquals(Z1, arithmeticFunction.add(X, Y));

		// subtraction
		int[] Z2 = { 6, 6, 6, 6, 6 };
		assertArrayEquals(Z2, arithmeticFunction.subtract(X, Y));

		// subtraction with underflow
		int[] Z3 = { 4, 4, 4, 4, 4 };
		assertArrayEquals(Z3, arithmeticFunction.subtract(Y, X));

		// addition
		int[] Z4 = { 4, 4, 4, 4, 4 };
		assertArrayEquals(Z4, arithmeticFunction.add(Y, Y));
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.FFX#FFX(int, int, int, int, boolean, org.fpe4j.FFX.FeistelMethod, org.fpe4j.FFX.SplitFunction, org.fpe4j.FFX.RoundCounter, org.fpe4j.FFX.RoundFunction)}.
	 */
	@Test
	public void testFFXIntIntIntIntBooleanFeistelMethodSplitFunctionRoundCounterRoundFunction() {

		// radix is too small
		try {
			new FFX(Constants.MINRADIX - 1, Constants.MINLEN, Constants.MAXLEN, Constants.MAXLEN, false,
					FeistelMethod.ONE, splitFunction1, roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// minlen is too small
		try {
			new FFX(Constants.MINRADIX, Constants.MINLEN - 1, Constants.MAXLEN, Constants.MAXLEN, false,
					FeistelMethod.ONE, splitFunction1, roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix^minlen is too small
		try {
			new FFX(Constants.MINRADIX, 6, Constants.MAXLEN, Constants.MAXLEN, false, FeistelMethod.ONE, splitFunction1,
					roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// maxlen is too small
		try {
			new FFX(Constants.MINRADIX, 7, Constants.MINLEN, Constants.MAXLEN, false, FeistelMethod.ONE, splitFunction1,
					roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// maxTlen is too small
		try {
			new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, -1, false, FeistelMethod.ONE, splitFunction1,
					roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// method is null
		try {
			new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, Constants.MAXLEN, false, null, splitFunction1,
					roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// split function is null
		try {
			new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, Constants.MAXLEN, false, FeistelMethod.ONE, null,
					roundCounter1, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// round count function is null
		try {
			new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, Constants.MAXLEN, false, FeistelMethod.ONE, splitFunction1,
					null, roundFunction1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// round function is null
		try {
			new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, Constants.MAXLEN, false, FeistelMethod.ONE, splitFunction1,
					roundCounter1, null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// blockwise
		new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, Constants.MAXLEN, true, FeistelMethod.ONE, splitFunction1,
				roundCounter1, roundFunction1);

		// charwise
		new FFX(Constants.MINRADIX, 7, Constants.MAXLEN, Constants.MAXLEN, false, FeistelMethod.ONE, splitFunction1,
				roundCounter1, roundFunction1);
	}

	/**
	 * Test method for {@link org.fpe4j.FFX#FFX(org.fpe4j.FFX.FFXParameters)}.
	 */
	@Test
	public void testFFXFFXParameters() {

		// params is null
		try {
			new FFX(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		FFXTestParameters params = new FFXTestParameters();

		params.radix = Constants.MINRADIX;
		params.minlen = Constants.MINLEN;
		params.maxlen = Constants.MAXLEN;
		params.minTlen = 0;
		params.maxTlen = Constants.MAXLEN;
		params.arithmeticFunction = FFX.getBlockwiseArithmeticFunction(params.radix);
		params.feistelMethod = FeistelMethod.ONE;
		params.splitFunction = splitFunction1;
		params.roundCounter = roundCounter1;
		params.roundFunction = roundFunction1;

		// radix is too small
		try {
			params.radix = Constants.MINRADIX - 1;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			params.radix = Constants.MINRADIX;
		}

		// minlen is too small
		try {
			params.minlen = Constants.MINLEN - 1;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix^minlen is too small
		try {
			params.minlen = 6;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			params.minlen = 7;
		}

		// maxlen is too small
		try {
			params.maxlen = params.minlen - 1;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			params.maxlen = Constants.MAXLEN;
		}

		// maxTlen is too small
		try {
			params.maxTlen = -1;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			params.maxTlen = Constants.MAXLEN;
		}

		// method is null
		try {
			params.feistelMethod = null;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
			params.feistelMethod = FeistelMethod.TWO;
		}

		// arithmetic function is null
		try {
			params.arithmeticFunction = null;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
			params.arithmeticFunction = FFX.getCharwiseArithmeticFunction(params.radix);
		}

		// split function is null
		try {
			params.splitFunction = null;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
			params.splitFunction = splitFunction1;
		}

		// round count function is null
		try {
			params.roundCounter = null;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
			params.roundCounter = roundCounter1;
		}

		// round function is null
		try {
			params.roundFunction = null;
			new FFX(params);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
			params.roundFunction = roundFunction1;
		}

		FFX ffx = new FFX(params);
		assertNotNull(ffx);
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.FFX#encrypt(javax.crypto.SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             only if there is a programming error in the test
	 */
	@Test
	public void testEncrypt() throws InvalidKeyException {
		FFXTestParameters params = new FFXTestParameters();
		params.radix = 10;
		params.minlen = 2;
		params.maxlen = 5;
		params.minTlen = 5;
		params.maxTlen = 5;
		params.arithmeticFunction = FFX.getBlockwiseArithmeticFunction(params.getRadix());
		params.feistelMethod = FeistelMethod.ONE;
		params.splitFunction = splitFunction1;
		params.roundCounter = roundCounter1;
		params.roundFunction = roundFunction1;
		FFX ffx = new FFX(params);

		byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
				(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
				(byte) 0x3C };
		byte[] tweak = { 0, 1, 2, 3, 4 };
		int[] plaintext = { 0, 1, 2, 3, 4 };
		int[] ciphertext1 = { 4, 5, 6, 7, 8 };
		int[] ciphertext2 = { 5, 6, 7, 8, 9 };

		// K is null
		try {
			SecretKeySpec K = null;
			byte[] T = tweak;
			int[] PT = plaintext;
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// K is invalid
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = tweak;
			int[] PT = plaintext;
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is null
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = null;
			int[] PT = plaintext;
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// T is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3 };
			int[] PT = plaintext;
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// T is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5 };
			int[] PT = plaintext;
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is null
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = null;
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0, 1, 2, 3, 4, 5 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short for radix
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// elements of X are not within the range 0..radix
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 10, 11, 12, 13, 14 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0, -1, -2, -3, -4 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// n == 2 * l && method == FeistelMethod.ONE && r < 8
		try {
			params.feistelMethod = FeistelMethod.ONE;
			params.roundCounter = roundCounter2;
			ffx = new FFX(params);
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0, 1, 2, 3 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// n != 2 * l && method == FeistelMethod.TWO && r < 8
		try {
			params.feistelMethod = FeistelMethod.TWO;
			params.roundCounter = roundCounter2;
			ffx = new FFX(params);
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0, 1, 2, 3, 4 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// n != 2 * l && method == FeistelMethod.ONE && r < 4 * n / l
		try {
			params.feistelMethod = FeistelMethod.ONE;
			params.roundCounter = roundCounter2;
			ffx = new FFX(params);
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] PT = { 0, 1, 2, 3, 4 };
			ffx.encrypt(K, T, PT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		SecretKeySpec K = new SecretKeySpec(key, "AES");

		// FeistelMethod.ONE
		params.feistelMethod = FeistelMethod.ONE;
		params.roundCounter = roundCounter1;
		ffx = new FFX(params);
		assertArrayEquals(ciphertext1, ffx.encrypt(K, tweak, plaintext));

		// FeistelMethod.TWO
		params.feistelMethod = FeistelMethod.TWO;
		params.roundCounter = roundCounter1;
		ffx = new FFX(params);
		assertArrayEquals(ciphertext2, ffx.encrypt(K, tweak, plaintext));
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.FFX#decrypt(javax.crypto.SecretKey, byte[], int[])}.
	 * 
	 * @throws InvalidKeyException
	 *             only if there is a programming error in the test
	 */
	@Test
	public void testDecrypt() throws InvalidKeyException {
		FFXTestParameters params = new FFXTestParameters();
		params.radix = 10;
		params.minlen = 2;
		params.maxlen = 5;
		params.minTlen = 5;
		params.maxTlen = 5;
		params.arithmeticFunction = FFX.getBlockwiseArithmeticFunction(params.getRadix());
		params.feistelMethod = FeistelMethod.ONE;
		params.splitFunction = splitFunction1;
		params.roundCounter = roundCounter1;
		params.roundFunction = roundFunction1;
		FFX ffx = new FFX(params);

		byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
				(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF, (byte) 0x4F,
				(byte) 0x3C };
		byte[] tweak = { 0, 1, 2, 3, 4 };
		int[] plaintext = { 0, 1, 2, 3, 4 };
		int[] ciphertext1 = { 4, 5, 6, 7, 8 };
		int[] ciphertext2 = { 5, 6, 7, 8, 9 };

		// K is null
		try {
			SecretKeySpec K = null;
			byte[] T = tweak;
			int[] CT = ciphertext1;
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// K is invalid
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("DES");
			SecretKey K = keygen.generateKey();
			byte[] T = tweak;
			int[] CT = ciphertext1;
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof InvalidKeyException);
		}

		// T is null
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = null;
			int[] CT = ciphertext1;
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// T is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3 };
			int[] CT = ciphertext1;
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// T is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = { 0, 1, 2, 3, 4, 5 };
			int[] CT = ciphertext1;
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is null
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = null;
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is too short
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too long
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0, 1, 2, 3, 4, 5 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too short for radix
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// elements of X are not within the range 0..radix
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 10, 11, 12, 13, 14 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0, -1, -2, -3, -4 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// n == 2 * l && method == FeistelMethod.ONE && r < 8
		try {
			params.feistelMethod = FeistelMethod.ONE;
			params.roundCounter = roundCounter2;
			ffx = new FFX(params);
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0, 1, 2, 3 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// n != 2 * l && method == FeistelMethod.TWO && r < 8
		try {
			params.feistelMethod = FeistelMethod.TWO;
			params.roundCounter = roundCounter2;
			ffx = new FFX(params);
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0, 1, 2, 3, 4 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// n != 2 * l && method == FeistelMethod.ONE && r < 4 * n / l
		try {
			params.feistelMethod = FeistelMethod.ONE;
			params.roundCounter = roundCounter2;
			ffx = new FFX(params);
			SecretKeySpec K = new SecretKeySpec(key, "AES");
			byte[] T = tweak;
			int[] CT = { 0, 1, 2, 3, 4 };
			ffx.decrypt(K, T, CT);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		SecretKeySpec K = new SecretKeySpec(key, "AES");

		// FeistelMethod.ONE
		params.feistelMethod = FeistelMethod.ONE;
		params.roundCounter = roundCounter1;
		ffx = new FFX(params);
		assertArrayEquals(plaintext, ffx.decrypt(K, tweak, ciphertext1));

		// FeistelMethod.TWO
		params.feistelMethod = FeistelMethod.TWO;
		params.roundCounter = roundCounter1;
		ffx = new FFX(params);
		assertArrayEquals(plaintext, ffx.decrypt(K, tweak, ciphertext2));
	}
}
