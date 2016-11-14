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

import static org.fpe4j.Common.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.fpe4j.FFX.ArithmeticFunction;
import org.fpe4j.FFX.FFXParameters;
import org.fpe4j.FFX.FeistelMethod;
import org.fpe4j.FFX.RoundCounter;
import org.fpe4j.FFX.RoundFunction;
import org.fpe4j.FFX.SplitFunction;

/**
 * FFX parameter set for the FF3 algorithm defined in NIST SP 80-38G.
 * 
 * @author Kai Johnson
 *
 */
public class FF3Parameters implements FFXParameters {

	/**
	 * The radix specified in this parameter set.
	 */
	final int radix;

	/**
	 * The minimum input length allowed by this parameter set.
	 */
	final int minlen;

	/**
	 * The maximum input length allowed by this parameter set.
	 */
	final int maxlen;

	/**
	 * Instances of AES ciphers for PRF and CIPH algorithms.
	 */
	final Ciphers ciphers;

	/**
	 * Arithmetic functions for the operations C = A [+] F K (n, T, i, B) in the
	 * encryption rounds and A = C [-] F K (n, T, i, B) in the decryption
	 * rounds.
	 * <p>
	 * The FF3 algorithm requires a little more generality than the FFX
	 * algorithm allows, because it uses a modified form of the arithmetic
	 * operations in the Feistel rounds.
	 * <p>
	 * FFX defines two types of arithmetic operators: blockwise arithmetic,
	 * which treats each input array as an integer [0..radix<sup>m</sup>], where
	 * m is the length of the array, and which returns a result within the same
	 * range; and characterwise arithmetic, which adds each array element
	 * individually and produces a resulting element within the range
	 * [0..radix].
	 * <p>
	 * FF3 uses a modified form of blockwise arithmetic, where the sequence of
	 * elements in the first array is reversed before the arithmetic operation,
	 * then the sequence of elements in the resulting array is reversed before
	 * it is returned.
	 */
	final FFX.ArithmeticFunction ff3ArithmeticFunction = new FFX.ArithmeticFunction() {

		@Override
		public int[] subtract(int[] X, int[] Y) {
			/*
			 * This corresponds to the following two steps from the FF3
			 * algorithm where X is B and Z is C:
			 * 
			 * v. Let c = (NUMradix (REV(B))–y) mod radix m .
			 * 
			 * vi. Let C = REV(STR m radix (c)).
			 */
			BigInteger x = num(rev(X), radix);
			BigInteger y = num(Y, radix);
			BigInteger z = mod(x.subtract(y), BigInteger.valueOf(radix).pow(X.length));
			int[] Z = str(z, radix, X.length);
			return rev(Z);
		}

		@Override
		public int[] add(int[] X, int[] Y) {
			/*
			 * This corresponds to the following two steps from the FF3
			 * algorithm where X is A and Z is C:
			 * 
			 * Step 6.v. Let c = (NUMradix (REV(A)) + y) mod radix.
			 * 
			 * Step 6.vi. Let C = REV(STR m radix (c)).
			 */
			BigInteger x = num(rev(X), radix);
			BigInteger y = num(Y, radix);
			BigInteger z = mod(x.add(y), BigInteger.valueOf(radix).pow(X.length));
			int[] Z = str(z, radix, X.length);
			return rev(Z);
		}
	};

	/**
	 * Split function for FF3.
	 */
	final FFX.SplitFunction ff3Splitter = new FFX.SplitFunction() {

		@Override
		public int split(int n) {
			// validate n
			if (n < minlen || n > maxlen)
				throw new IllegalArgumentException("n must be in the range [" + minlen + ".." + maxlen + "].");

			return ceiling(n / 2.0);
		}
	};

	/**
	 * Function to determine the number of Feistel rounds for FF3.
	 */
	final FFX.RoundCounter ff3RoundCounter = new FFX.RoundCounter() {

		@Override
		public int rnds(int n) {
			return 8;
		}
	};

	/**
	 * Round function F for FF1, derived from NIST SP 800-38G.
	 */
	final FFX.RoundFunction ff3Round = new FFX.RoundFunction() {

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

			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Round #" + i + "\n");
			}

			// value of REVB(K) for readability
			SecretKeySpec revK = new SecretKeySpec(revb(K.getEncoded()), "AES");
			/*
			 * Note that this only works if K is in RAW format, but that FFX
			 * checks this by calling validKey() before calling F.
			 */

			// 1. Let u = ceiling(n/2); v = n – u.
			int u = ceiling(n / 2.0);
			int v = n - u;
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 1\n\tu is <" + u + ">, and v is <" + v + ">");
			}

			// 2. Let A = X[1..u]; B = X[u + 1..n].
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 2\n\tB is " + Common.intArrayToString(B));
			}

			// 3. Let T_L = T[0..31] and T_R = T[32..63]
			byte[] T_L = Arrays.copyOfRange(T, 0, 4);
			byte[] T_R = Arrays.copyOfRange(T, 4, 8);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println(
						"Step 3\n\tT_L is " + byteArrayToHexString(T_L) + "\n\tT_R is " + byteArrayToHexString(T_R));
			}

			// i. If i is even, let m = u and W = T_R ,
			// else let m = v and W = T_L .
			int m = i % 2 == 0 ? u : v;
			byte[] W = i % 2 == 0 ? T_R : T_L;
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 4.i\n\tm is <" + m + ">\n\tW is " + byteArrayToHexString(W));
			}

			// ii. Let P = W xor [i] 4 || [NUMradix (REV(B))] 12 .
			byte[] P = concatenate(xor(W, bytestring(i, 4)), bytestring(num(rev(B), radix), 12));
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 4.ii\n\tP is " + Common.unsignedByteArrayToString(P));
			}

			// iii Let S = REVB(CIPH REVB(K) REVB(P)).
			byte[] S = revb(ciphers.ciph(revK, revb(P)));
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 4.iii\n\tS is " + byteArrayToHexString(S));
			}

			// iv. Let y = NUM(S).
			BigInteger y = num(S);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 4.iv\n\ty is " + y);
			}

			// constrain y to the range [0..radix^m]
			y = Common.mod(y, BigInteger.valueOf(radix).pow(m));

			// 5. Let Y = STR m radix (y).
			int[] Y = str(y, radix, m);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 5.\n\tY is " + Common.intArrayToString(Y) + "\n");
			}

			return Y;
		}
	};

	/**
	 * Construct a new FF3Parameters instance with the specified radix.
	 * 
	 * @param radix
	 *            the radix for FF3 operations
	 */
	public FF3Parameters(int radix) {
		this.radix = radix;

		// 2 <= minlen <= maxlen <= 2 * floor(log(2^96)/log(radix))
		minlen = Math.max(2, ceiling(Math.log(100) / Math.log(radix)));
		maxlen = Math.max(minlen, 2 * floor(Math.log(Math.pow(2, 96)) / Math.log(radix)));

		ciphers = new Ciphers();
	}

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
		return 8;
	}

	@Override
	public int getMaxTLen() {
		return 8;
	}

	@Override
	public ArithmeticFunction getArithmeticFunction() {
		return ff3ArithmeticFunction;
	}

	@Override
	public FeistelMethod getFeistelMethod() {
		return FeistelMethod.TWO;
	}

	@Override
	public SplitFunction getSplitter() {
		return ff3Splitter;
	}

	@Override
	public RoundCounter getRoundCounter() {
		return ff3RoundCounter;
	}

	@Override
	public RoundFunction getRoundFunction() {
		return ff3Round;
	}
}
