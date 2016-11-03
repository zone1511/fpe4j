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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * Implementation of the FFX algorithm described in <a href=
 * "http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.1736&rep=rep1&type=pdf">The
 * FFX Mode of Operation for Format-Preserving Encryption</a>, by Mihir Bellare,
 * Phillip Rogaway, and Terence Spies.
 * <p>
 * To use this class, you must construct an instance using either of the
 * constructors, then call the encrypt() and/or decrypt() methods. At a minimum,
 * you must supply the split(n), rnds(n) and F(K,n,T,i,B) functions, along with
 * the other FFX parameters.
 * <p>
 * The round function F must be constructed from a block cipher or hash
 * function. For AES, the CBC MAC and CMAC modes are recommended. For hash
 * functions, F could be constructed using HMAC.
 * <p>
 * At best, FFX is only as secure as the supplied parameter sets. At its worst,
 * FFX may produce output that is less secure than the underlying block cipher
 * or hash function.
 * <p>
 * FFX itself, and this implementation in particular, may not be an efficient
 * way to implement a specific FPE function derived from FFX. The generality of
 * FFX precludes some optimizations that may be possible in more direct
 * implementation of a single FPE algorithm.
 * 
 * @author Kai Johnson
 *
 */
public class FFX {

	/**
	 * The range of values for symbols in plaintexts and ciphertexts, 0..radix
	 * for each symbol.
	 */
	private final int radix;

	/**
	 * The minimum length of plaintext and ciphertext inputs.
	 */
	private final int minlen;

	/**
	 * The maximum length of plaintext and ciphertext inputs.
	 */
	private final int maxlen;

	/**
	 * The minimum length of tweak inputs.
	 */
	private final int minTlen;

	/**
	 * The maximum length of tweak inputs.
	 */
	private final int maxTlen;

	/**
	 * The arithmetic functions for the [+] and [-] operations in the Feistel
	 * rounds.
	 */
	private final ArithmeticFunction arithmeticFunction;

	/**
	 * The Feistel method, either ONE where the array is re-partitioned on each
	 * round, or TWO where the array partitions are swapped on each round.
	 */
	private final FeistelMethod feistelMethod;

	/**
	 * Function to determine where to split input arrays.
	 */
	private final SplitFunction splitter;

	/**
	 * Function to determine the number of Feistel rounds.
	 */
	private final RoundCounter roundCounter;

	/**
	 * Pseudorandom function for Feistel rounds.
	 */
	private final RoundFunction roundFunction;

	/**
	 * Types of Feistel methods
	 * 
	 * @author Kai Johnson
	 *
	 */
	public enum FeistelMethod {
		/**
		 * Array is re-partitioned on each round.
		 */
		ONE,

		/**
		 * Array partitions are swapped on each round.
		 */
		TWO
	}

	/**
	 * Function to determine where to split input arrays.
	 * 
	 * @author Kai Johnson
	 *
	 */
	public interface SplitFunction {
		/**
		 * The imbalance, a function that takes a permitted length n in the
		 * range [minlen..maxlen] and returns a number 1 &lt;= split(n) &lt;=
		 * n/2.
		 * 
		 * @param n
		 *            the length
		 * @return the degree of imbalance
		 * @throws IllegalArgumentException
		 *             if n is not in the range [minlen..maxlen]
		 */
		public int split(int n);
	}

	/**
	 * Function to determine the number of Feistel rounds.
	 * 
	 * @author Kai Johnson
	 *
	 */
	public interface RoundCounter {
		/**
		 * Returns the number of Feistel rounds for an input of length n.
		 * 
		 * @param n
		 *            the length of the input
		 * @return the number of Feistel rounds
		 * @throws IllegalArgumentException
		 *             if n is not in the range [minlen..maxlen]
		 */
		public int rnds(int n);
	}

	/**
	 * Pseudorandom function for Feistel rounds.
	 * 
	 * @author Kai Johnson
	 *
	 */
	public interface RoundFunction {
		/**
		 * Pseudorandom function for Feistel rounds.
		 * 
		 * @param K
		 *            the encryption key of a type compatible with the
		 *            underlying cipher
		 * @param n
		 *            the original length of the input
		 * @param T
		 *            the tweak
		 * @param i
		 *            the index of the current round, in the range [0..rnds(n)]
		 * @param B
		 *            the array partition to transform
		 * @return an array of the same length as A (i.e. n - B.length) with
		 *         pseudorandom values in the range [0..radix]
		 * @throws InvalidKeyException
		 *             if the key is invalid or not compatible with the
		 *             underlying cipher
		 * @throws IllegalArgumentException
		 *             If n is not within the range [minlen..maxlen]; the length
		 *             of T is not within the range of [minTlen..maxTlen]; the
		 *             length of B is not within the range [1..ceiling(n/2)]; ;
		 *             or any value B[i] is not in the range [0..radix].
		 */
		public int[] F(SecretKey K, int n, byte[] T, int i, int[] B) throws InvalidKeyException;

		/**
		 * Validates the key for the psuedorandom function.
		 * 
		 * @param K
		 *            the key
		 * @return true if the key is compatible with the underlying cipher.
		 */
		public boolean validKey(SecretKey K);
	}

	/**
	 * The arithmetic functions for the [+] and [-] operations in the Feistel
	 * rounds.
	 * 
	 * @author Kai Johnson
	 *
	 */
	protected interface ArithmeticFunction {
		/**
		 * Add Y to X
		 * 
		 * @param X
		 *            the first operand with elements in the range [0..radix]
		 * @param Y
		 *            the second operand with elements in the range [0..radix]
		 * @return the result of X [+] Y with length = X.length = Y.length and
		 *         elements each in the range [0..radix]
		 * @throws NullPointerException
		 *             if X or Y is null
		 * @throws IllegalArgumentException
		 *             if X.length != Y.length, or if any X[i] or Y[i] is not in
		 *             the range [0..radix]
		 */
		public int[] add(int[] X, int[] Y);

		/**
		 * Subtract Y from X
		 * 
		 * @param X
		 *            the first operand with elements in the range [0..radix]
		 * @param Y
		 *            the second operand with elements in the range [0..radix]
		 * @return the result of X [-] Y with length = X.length = Y.length and
		 *         elements each in the range [0..radix]
		 * @throws IllegalArgumentException
		 *             if X.length != Y.length, or if any X[i] or Y[i] is not in
		 *             the range [0..radix]
		 */
		public int[] subtract(int[] X, int[] Y);
	}

	/**
	 * FFX parameter set.
	 * 
	 * @author Kai Johnson
	 *
	 */
	public interface FFXParameters {
		/**
		 * @return the radix
		 */
		int getRadix();

		/**
		 * @return the minimum length for plaintext and ciphertext inputs
		 */
		int getMinLen();

		/**
		 * @return the maximum length for plaintext and ciphertext inputs
		 */
		int getMaxLen();

		/**
		 * @return the minimum length for tweaks
		 */
		int getMinTLen();

		/**
		 * @return the maximum length for tweaks
		 */
		int getMaxTLen();

		/**
		 * @return the arithmetic functions for the [+] and [-] operations in
		 *         the Feistel rounds
		 */
		ArithmeticFunction getArithmeticFunction();

		/**
		 * @return the Feistel method
		 */
		FeistelMethod getFeistelMethod();

		/**
		 * @return the function to determine where to split input arrays
		 */
		SplitFunction getSplitter();

		/**
		 * @return the function to determine the number of Feistel rounds
		 */
		RoundCounter getRoundCounter();

		/**
		 * @return the Feistel round function
		 */
		RoundFunction getRoundFunction();
	}

	/**
	 * Returns an ArithmeticFunction instance which implements blockwise
	 * arithmetic, treating each input array as an integer
	 * [0..radix<sup>m</sup>], where m is the length of the array, and returning
	 * an array representing a result within the same range.
	 * 
	 * @param radix
	 *            the radix
	 * @return an ArithmeticFunction which implements blockwise addition for the
	 *         specified radix
	 * 
	 */
	public static ArithmeticFunction getBlockwiseArithmeticFunction(int radix) {
		// validate radix
		if (radix < Constants.MINRADIX)
			throw new IllegalArgumentException("Radix must be greater than " + Constants.MINRADIX);

		return new ArithmeticFunction() {
			@Override
			public int[] add(int[] X, int[] Y) {
				// validate X
				if (X == null)
					throw new NullPointerException("X must not be null.");
				if (X.length == 0)
					throw new IllegalArgumentException("X must not be empty");

				// validate Y
				if (Y == null)
					throw new NullPointerException("Y must not be null.");
				if (Y.length == 0)
					throw new IllegalArgumentException("Y must not be empty");
				if (X.length != Y.length)
					throw new IllegalArgumentException("X and Y must be the same length.");

				// numeric value of X
				BigInteger x = Common.num(X, radix);

				// numeric value of Y
				BigInteger y = Common.num(Y, radix);

				// numeric value of (x + y) mod radix^m
				BigInteger z = Common.mod(x.add(y), BigInteger.valueOf(radix).pow(X.length));

				// convert result to an array
				int[] Z = Common.str(z, radix, X.length);

				return Z;
			}

			@Override
			public int[] subtract(int[] X, int[] Y) {
				// validate X
				if (X == null)
					throw new NullPointerException("X must not be null.");
				if (X.length == 0)
					throw new IllegalArgumentException("X must not be empty");

				// validate Y
				if (Y == null)
					throw new NullPointerException("Y must not be null.");
				if (Y.length == 0)
					throw new IllegalArgumentException("Y must not be empty");
				if (X.length != Y.length)
					throw new IllegalArgumentException("X and Y must be the same length.");

				// numeric value of X
				BigInteger x = Common.num(X, radix);

				// numeric value of Y
				BigInteger y = Common.num(Y, radix);

				// numeric value of (x - y) mod radix^m
				BigInteger z = Common.mod(x.subtract(y), BigInteger.valueOf(radix).pow(X.length));

				// convert result to an array
				int[] Z = Common.str(z, radix, X.length);
				return Z;
			}
		};
	}

	/**
	 * Returns an ArithmeticFunction instance which implements characterwise
	 * arithmetic, performing modulo arithmetic on the corresponding elements of
	 * each input array, and returning an array of the same length as the input
	 * arrays with elements in the range [0..radix].
	 * 
	 * @param radix
	 *            the radix
	 * @return an ArithmeticFunction which implements blockwise addition for the
	 *         specified radix
	 * 
	 */
	public static ArithmeticFunction getCharwiseArithmeticFunction(int radix) {
		// validate radix
		if (radix < Constants.MINRADIX)
			throw new IllegalArgumentException("Radix must be greater than " + Constants.MINRADIX);

		return new ArithmeticFunction() {
			@Override
			public int[] add(int[] X, int[] Y) {
				// validate X
				if (X == null)
					throw new NullPointerException("X must not be null.");
				if (X.length == 0)
					throw new IllegalArgumentException("X must not be empty");

				// validate Y
				if (Y == null)
					throw new NullPointerException("Y must not be null.");
				if (Y.length == 0)
					throw new IllegalArgumentException("Y must not be empty");
				if (X.length != Y.length)
					throw new IllegalArgumentException("X and Y must be the same length.");

				// create the result array
				int[] Z = new int[X.length];

				// for each element in the input arrays
				for (int i = 0; i < X.length; i++) {
					// z = (x + y) mod radix
					Z[i] = Common.mod(X[i] + Y[i], radix);
				}
				return Z;
			}

			@Override
			public int[] subtract(int[] X, int[] Y) {
				// validate X
				if (X == null)
					throw new NullPointerException("X must not be null.");
				if (X.length == 0)
					throw new IllegalArgumentException("X must not be empty");

				// validate Y
				if (Y == null)
					throw new NullPointerException("Y must not be null.");
				if (Y.length == 0)
					throw new IllegalArgumentException("Y must not be empty");
				if (X.length != Y.length)
					throw new IllegalArgumentException("X and Y must be the same length.");

				// create the result array
				int[] Z = new int[X.length];

				// for each element in the input arrays
				for (int i = 0; i < X.length; i++) {
					// z = (x - y) mod radix
					Z[i] = Common.mod(X[i] - Y[i], radix);
				}
				return Z;
			}
		};
	}

	/**
	 * Construct a new FFX instance from explicit parameters.
	 * 
	 * @param radix
	 *            The range of values for symbols in plaintexts and ciphertexts,
	 *            0..radix for each symbol.
	 * @param minlen
	 *            The minimum length of plaintext and ciphertext inputs.
	 * @param maxlen
	 *            The maximum length of plaintext and ciphertext inputs.
	 * @param maxTlen
	 *            The maximum length of tweak inputs.
	 * @param blockwise
	 *            True if the functions for the [+] and [-] operations in the
	 *            Feistel rounds are blockwise arithmetic, false if the
	 *            functions use charwise arithmetic
	 * @param method
	 *            The Feistel method, either ONE where the array is
	 *            re-partitioned on each round, or TWO where the array
	 *            partitions are swapped on each round.
	 * @param split
	 *            Function to determine where to split input arrays.
	 * @param rnds
	 *            Function to determine the number of Feistel rounds.
	 * @param F
	 *            Pseudorandom function for Feistel rounds.
	 */
	public FFX(int radix, int minlen, int maxlen, int maxTlen, boolean blockwise, FeistelMethod method,
			SplitFunction split, RoundCounter rnds, RoundFunction F) {
		// validate radix
		if (radix < Constants.MINRADIX)
			throw new IllegalArgumentException(
					"radix must be greater than or equal to " + Constants.MINRADIX + ": " + radix);

		// validate minlen
		if (minlen < Constants.MINLEN)
			throw new IllegalArgumentException(
					"minlen must be greater than or equal to " + Constants.MINLEN + ": " + minlen);
		if (Math.pow(radix, minlen) < 100) {
			throw new IllegalArgumentException(
					"radix^minlen must be greater than or equal to 100: " + Math.pow(radix, minlen));
		}

		// validate maxlen
		if (maxlen < minlen)
			throw new IllegalArgumentException("maxlen must be greater than or equal to minlen: " + maxlen);

		// validate maxTlen;
		if (maxTlen < 0)
			throw new IllegalArgumentException("maxTlen must be greater than or equal to zero: " + maxTlen);

		// validate method
		if (method == null)
			throw new NullPointerException("method must not be null.");

		// validate split function
		if (split == null)
			throw new NullPointerException("Split function must not be null.");

		// validate round count function
		if (rnds == null)
			throw new NullPointerException("Round count function must not be null.");

		// validate round function
		if (F == null)
			throw new NullPointerException("F must not be null.");

		// initialize instance variables
		this.radix = radix;
		this.minlen = minlen;
		this.maxlen = maxlen;
		minTlen = 0;
		this.maxTlen = maxTlen;
		if (blockwise) {
			arithmeticFunction = getBlockwiseArithmeticFunction(radix);
		} else {
			arithmeticFunction = getCharwiseArithmeticFunction(radix);
		}
		feistelMethod = method;
		splitter = split;
		roundCounter = rnds;
		roundFunction = F;
	}

	/**
	 * Construct a new FFX instance from an FFXParameter object.
	 * 
	 * @param params
	 *            the parameters for the FFX instance
	 */
	public FFX(FFXParameters params) {

		// validate params
		if (params == null)
			throw new NullPointerException("Params must not be null.");

		// initialize instance variables
		radix = params.getRadix();
		minlen = params.getMinLen();
		maxlen = params.getMaxLen();
		minTlen = params.getMinTLen();
		maxTlen = params.getMaxTLen();
		arithmeticFunction = params.getArithmeticFunction();
		feistelMethod = params.getFeistelMethod();
		splitter = params.getSplitter();
		roundCounter = params.getRoundCounter();
		roundFunction = params.getRoundFunction();

		// validate radix
		if (radix < 2)
			throw new IllegalArgumentException("radix must be greater than or equal to 2: " + radix);

		// validate minlen
		if (minlen < 2)
			throw new IllegalArgumentException("minlen must be greater than or equal to 2: " + minlen);
		if (Math.pow(radix, minlen) < 100) {
			throw new IllegalArgumentException(
					"radix^minlen must be greater than or equal to 100: " + Math.pow(radix, minlen));
		}

		// validate maxlen
		if (maxlen < minlen)
			throw new IllegalArgumentException("maxlen must be greater than or equal to minlen: " + maxlen);

		// validate maxTlen;
		if (maxTlen < 0)
			throw new IllegalArgumentException("maxTlen must be greater than or equal to zero: " + maxTlen);

		// validate method
		if (feistelMethod == null)
			throw new NullPointerException("method must not be null.");

		// validate arithmetic function
		if (arithmeticFunction == null)
			throw new NullPointerException("Arithmetic function must not be null.");

		// validate split function
		if (splitter == null)
			throw new NullPointerException("Split function must not be null.");

		// validate round count function
		if (roundCounter == null)
			throw new NullPointerException("Round count function must not be null.");

		// validate round function
		if (roundFunction == null)
			throw new NullPointerException("F must not be null.");
	}

	/**
	 * FFX.Encrypt(K, T, X) - Encrypts a plaintext string of numerals and
	 * produces a ciphertext string of numerals of the same length and radix.
	 * <p>
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            The tweak with length in the range [minTlen..maxTlen].
	 * @param X
	 *            The plaintext numeral string with length in the range
	 *            [minlen..maxlen] and element values in the range [0..radix].
	 * @return The ciphertext numeral string of the same length with element
	 *         values in the same range.
	 * @throws NullPointerException
	 *             If any of the arguments are null.
	 * @throws IllegalArgumentException
	 *             If the length of T is not within the range of
	 *             [minTlen..maxTlen]; the length of X is not within the range
	 *             [minlen..maxlen]; radix<sup>X.length</sup> is less than 100;
	 *             or any value X[i] is not in the range [0..radix].
	 * @throws InvalidKeyException
	 *             If K is not a valid key for the underlying cipher.
	 */
	public int[] encrypt(SecretKey K, byte[] T, int[] X) throws InvalidKeyException {
		// if K is not in the set of Keys or T is not in the set of Tweaks or X
		// is not in the set of Chars* or |X| is not in the set of Lengths then
		// return null (i.e. throw an appropriate exception)

		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null.");
		if (!roundFunction.validKey(K))
			throw new InvalidKeyException("K is not a valid key for F.");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null.");
		if (T.length < minTlen || T.length > maxTlen)
			throw new IllegalArgumentException(
					"The length of T must be in the range [" + minTlen + ".." + maxTlen + "]: " + T.length);

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null.");
		if (X.length < minlen)
			throw new IllegalArgumentException(
					"The length of X must be greater than or equal to " + minlen + ": " + X.length);
		if (X.length > maxlen)
			throw new IllegalArgumentException(
					"The length of X must be less than or equal to " + maxlen + ": " + X.length);
		for (int x : X) {
			if (x < 0 || x >= radix)
				throw new IllegalArgumentException("The elements of X must be in the range 0.." + (radix - 1));
		}

		// n <- |X|; l <- split(n); r <- rnds(n)
		int n = X.length;
		int l = splitter.split(n);
		int r = roundCounter.rnds(n);

		/*
		 * To avoid known attacks, we require that rnds(n) >= 8 if n = 2 *
		 * split(n) or if method = 2 and n = 2 * split(n) + 1, and we require
		 * that rnds(n) >= 4n/split(n) otherwise.
		 */

		// validate rounds
		if ((n == 2 * l || feistelMethod == FeistelMethod.TWO) && r < 8)
			throw new IllegalArgumentException(
					"FFX requires a minimum of eight rounds for balanced splits or method two: " + r);
		else if (r < 4 * n / l)
			throw new IllegalArgumentException(
					"FFX requires a minimum of " + 4 * n / l + " rounds for method one with imbalanced splits.");

		// if method = 1 then
		if (feistelMethod == FeistelMethod.ONE) {
			// for i <- 0 to r - 1 do
			for (int i = 0; i < r; i++) {
				// A <- X[1..l]; B <- X[l + 1..n]
				int[] A = Arrays.copyOfRange(X, 0, l);
				int[] B = Arrays.copyOfRange(X, l, n);

				// C <- A [+] F K (n, T, i, B)
				int[] C = arithmeticFunction.add(A, roundFunction.F(K, n, T, i, B));

				// X <- B || C
				X = Common.concatenate(B, C);
			}
			// return X
			return X;

		} else /* if method = 2 then */ {
			// A <- X[1..l]; B <- X[l + 1..n]
			int[] A = Arrays.copyOfRange(X, 0, l);
			int[] B = Arrays.copyOfRange(X, l, n);

			// for i <- 0 to r - 1 do
			for (int i = 0; i < r; i++) {

				// C <- A [+] F K (n, T, i, B)
				int[] C = arithmeticFunction.add(A, roundFunction.F(K, n, T, i, B));

				// A <- B; B <- C
				A = B;
				B = C;
			}
			// return A || B
			return Common.concatenate(A, B);
		}
	}

	/**
	 * FFX.Decrypt(K, T, Y) - Decrypts a ciphertext string of numerals and
	 * produces a plaintext string of numerals of the same length and radix.
	 * <p>
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            The tweak with length in the range [minTlen..maxTlen].
	 * @param Y
	 *            The ciphertext numeral string with length in the range
	 *            [minlen..maxlen] and element values in the range [0..radix].
	 * @return The plaintext numeral string of the same length with element
	 *         values in the same range.
	 * @throws NullPointerException
	 *             If any of the arguments are null.
	 * @throws IllegalArgumentException
	 *             If the length of T is not within the range of
	 *             [minTlen..maxTlen]; the length of X is not within the range
	 *             [minlen..maxlen]; radix<sup>X.length</sup> is less than 100;
	 *             or any value X[i] is not in the range [0..radix].
	 * @throws InvalidKeyException
	 *             If K is not a valid key for the underlying cipher.
	 */
	public int[] decrypt(SecretKey K, byte[] T, int[] Y) throws InvalidKeyException {
		// algorithm FFX.Decrypt(K, T, Y )

		// end if

		// if K is not in the set of Keys or T is not in the set of Tweaks or Y
		// is not in the set of Chars or |Y| is not in the set of Lengths then
		// return null (i.e. throw an appropriate exception)

		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null.");
		if (!roundFunction.validKey(K))
			throw new InvalidKeyException("K is not a valid key for F.");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null.");
		if (T.length < minTlen || T.length > maxTlen)
			throw new IllegalArgumentException(
					"The length of T must be in the range [" + minTlen + ".." + maxTlen + "]: " + T.length);

		// validate X
		if (Y == null)
			throw new NullPointerException("X must not be null.");
		if (Y.length < minlen)
			throw new IllegalArgumentException(
					"The length of X must be greater than or equal to " + minlen + ": " + Y.length);
		if (Y.length > maxlen)
			throw new IllegalArgumentException(
					"The length of X must be less than or equal to " + maxlen + ": " + Y.length);
		for (int x : Y) {
			if (x < 0 || x >= radix)
				throw new IllegalArgumentException("The elements of X must be in the range 0.." + (radix - 1));
		}

		// n <- |Y| ; l <- split(n); r <- rnds(n)
		int n = Y.length;
		int l = splitter.split(n);
		int r = roundCounter.rnds(n);

		/*
		 * To avoid known attacks, we require that rnds(n) >= 8 if n = 2 *
		 * split(n) or if method = 2 and n = 2 * split(n) + 1, and we require
		 * that rnds(n) >= 4n/split(n) otherwise.
		 */

		// validate rounds
		if ((n == 2 * l || feistelMethod == FeistelMethod.TWO) && r < 8)
			throw new IllegalArgumentException(
					"FFX requires a minimum of eight rounds for balanced splits or method two: " + r);
		else if (r < 4 * n / l)
			throw new IllegalArgumentException(
					"FFX requires a minimum of " + 4 * n / l + " rounds for method one with imbalanced splits.");

		// if method = 1 then
		if (feistelMethod == FeistelMethod.ONE) {
			// for i <- r - 1 downto 0 do
			for (int i = r - 1; i >= 0; i--) {
				// B <- Y [1..n - l]; C <- Y [n - l + 1..n]
				int[] B = Arrays.copyOfRange(Y, 0, n - l);
				int[] C = Arrays.copyOfRange(Y, n - l, n);

				// A <- C [-] F K (n, T, i, B)
				int[] A = arithmeticFunction.subtract(C, roundFunction.F(K, n, T, i, B));

				// Y <- A || B
				Y = Common.concatenate(A, B);
			}
			// return Y
			return Y;
		} else /* if method = 2 then */ {
			// A <- Y [1..l]; B <- Y [l + 1..n]
			int[] A = Arrays.copyOfRange(Y, 0, l);
			int[] B = Arrays.copyOfRange(Y, l, n);

			// for i <- r - 1 downto 0 do
			for (int i = r - 1; i >= 0; i--) {
				// C <- B; B <- A
				int[] C = B;
				B = A;

				// A <- C [-] F K (n, T, i, B)
				A = arithmeticFunction.subtract(C, roundFunction.F(K, n, T, i, B));
			}
			// return A || B
			return Common.concatenate(A, B);
		}
	}
}
