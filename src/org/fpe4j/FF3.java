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

/**
 * Implementation of the FF3 method for format-preserving encryption defined in
 * NIST SP 800-38G.
 * <p>
 * To use this class, construct an instance and call the encrypt() and/or
 * decrypt() methods.
 * 
 * @author Kai Johnson
 *
 */
public class FF3 {

	/**
	 * The radix for symbols to be processed by FF3.
	 */
	private final int radix;

	/**
	 * The minimum number of symbols permitted in plaintext and ciphertext
	 * values.
	 */
	private final int minlen;

	/**
	 * The maximum number of symbols permitted in plaintext and ciphertext
	 * values.
	 */
	private final int maxlen;

	/**
	 * Ciphers instance to provide common cipher functions.
	 */
	private final Ciphers mCiphers;

	/**
	 * Construct a new FF3 instance with a given radix.
	 * 
	 * @param radix
	 *            The radix for symbols to be processed by this instance.
	 * @throws IllegalArgumentException
	 *             If the radix is not in the range
	 *             [{@value org.fpe4j.Constants#MINRADIX}..{@value org.fpe4j.Constants#MAXRADIX}].
	 */
	FF3(int radix) {
		if (radix < Constants.MINRADIX || radix > Constants.MAXRADIX)
			throw new IllegalArgumentException("Radix must be in the range 2..65536: " + radix);
		this.radix = radix;

		// 2 <= minlen <= maxlen <= 2 * floor(log(2^96)/log(radix))
		minlen = Math.max(2, ceiling(Math.log(100) / Math.log(radix)));
		maxlen = Math.max(minlen, 2 * floor(Math.log(Math.pow(2, 96)) / Math.log(radix)));

		mCiphers = new Ciphers();
	}

	/**
	 * Returns the minimum length of plaintext and ciphertext inputs based on
	 * the radix.
	 * 
	 * @return The minimum length of plaintext and ciphertext inputs based on
	 *         the radix.
	 */
	public int getMinlen() {
		return minlen;
	}

	/**
	 * Returns the maximum length of plaintext and ciphertext inputs based on
	 * the radix.
	 * 
	 * @return The maximum length of plaintext and ciphertext inputs based on
	 *         the radix.
	 */
	public int getMaxlen() {
		return maxlen;
	}

	/**
	 * NIST SP 800-38G Algorithm 9: FF3.Encrypt(K, T, X) - Encrypt a plaintext
	 * string of numerals and produce a ciphertext string of numerals of the
	 * same length and radix.
	 * <p>
	 * Prerequisites:<br>
	 * Designated cipher function, CIPH, of an approved 128-bit block
	 * cipher;<br>
	 * Key, K, for the block cipher;<br>
	 * Base, radix;<br>
	 * Range of supported message lengths, [minlen..maxlen].<br>
	 * <p>
	 * Inputs: <br>
	 * Numeral string, X, in base radix of length n, such that n is in the range
	 * [minlen..maxlen]<br>
	 * Tweak bit string, T, such that LEN(T) = 64.
	 * <p>
	 * Output:<br>
	 * Numeral string, Y, such that LEN(Y) = n.
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            8-byte tweak array.
	 * @param X
	 *            The plaintext numeral string.
	 * @return The ciphertext numeral string of the same length and radix.
	 * @throws NullPointerException
	 *             If any of the arguments are null.
	 * @throws InvalidKeyException
	 *             If K is not a valid AES key.
	 * @throws IllegalArgumentException
	 *             If T is not 8 bytes long; the length of X is not within the
	 *             range [minlen..maxlen]; or any value X[i] is not in the range
	 *             [0..radix].
	 */
	public int[] encrypt(SecretKey K, byte[] T, int[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be an AES key");
		if (!K.getFormat().equals("RAW"))
			throw new InvalidKeyException("K must be in RAW format");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null");
		if (T.length != 8)
			throw new IllegalArgumentException("T must be an array of 8 bytes: " + T.length);

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < minlen || X.length > maxlen)
			throw new IllegalArgumentException(
					"The length of X is not within the permitted range of " + minlen + ".." + maxlen + ": " + X.length);

		if (Constants.CONFORMANCE_OUTPUT) {
			System.out.println("FF3.Encrypt()\n");
			System.out.println("X is " + intArrayToString(X));
			System.out.println("Tweak is " + byteArrayToHexString(T) + "\n");
		}

		// value of n for readability
		int n = X.length;

		// value of REVB(K) for readability
		SecretKeySpec revK = new SecretKeySpec(revb(K.getEncoded()), "AES");
		/*
		 * Note that this only works if K is in RAW format.
		 */

		// 1. Let u = ceiling(n/2); v = n – u.
		int u = ceiling(n / 2.0);
		int v = n - u;
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 1\n\tu is <" + u + ">, and v is <" + v + ">");

		// 2. Let A = X[1..u]; B = X[u + 1..n].
		int[] A = Arrays.copyOfRange(X, 0, u);
		int[] B = Arrays.copyOfRange(X, u, n);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 2\n\tA is " + intArrayToString(A) + "\n\tB is " + intArrayToString(B));

		// 3. Let T_L = T[0..31] and T_R = T[32..63]
		byte[] T_L = Arrays.copyOfRange(T, 0, 4);
		byte[] T_R = Arrays.copyOfRange(T, 4, 8);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println(
					"Step 3\n\tT_L is " + byteArrayToHexString(T_L) + "\n\tT_R is " + byteArrayToHexString(T_R) + "\n");

		// 4. For i from 0 to 7:
		for (int i = 0; i < 8; i++) {
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("Round #" + i);

			// i. If i is even, let m = u and W = T_R ,
			// else let m = v and W = T_L .
			int m = i % 2 == 0 ? u : v;
			byte[] W = i % 2 == 0 ? T_R : T_L;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.i\n\t\tm is <" + m + ">\n\t\tW is " + byteArrayToHexString(W));

			// ii. Let P = W xor [i] 4 || [NUMradix (REV(B))] 12 .
			byte[] P = concatenate(xor(W, bytestring(i, 4)), bytestring(num(rev(B), radix), 12));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.ii\n\t\tP is " + unsignedByteArrayToString(P));

			// iii Let S = REVB(CIPH REVB(K) REVB(P)).
			byte[] S = revb(mCiphers.ciph(revK, revb(P)));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.iii\n\t\tS is " + byteArrayToHexString(S));

			// iv. Let y = NUM(S).
			BigInteger y = num(S);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.iv\n\t\ty is " + y);

			// v. Let c = (NUMradix (REV(A)) + y) mod radix m .
			BigInteger c = mod(num(rev(A), radix).add(y), BigInteger.valueOf(radix).pow(m));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.v\n\t\tc is " + c);

			// vi. Let C = REV(STR m radix (c)).
			int[] C = rev(str(c, radix, m));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.vi\n\t\tC is " + intArrayToString(C));

			// vii. Let A = B.
			A = B;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.vii\n\t\tA is " + intArrayToString(A));

			// viii. Let B = C.
			B = C;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.viii\n\t\tB is " + intArrayToString(B));
		}
		// 5. Return A || B.
		int[] AB = concatenate(A, B);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 5\n\tA || B is " + intArrayToString(AB));
		return AB;
	}

	/**
	 * NIST SP 800-38G Algorithm 10: FF3.Decrypt(K, T, X) - Decrypt a ciphertext
	 * string of numerals and produce a plaintext string of numerals of the same
	 * length and radix.
	 * <p>
	 * Prerequisites:<br>
	 * Designated cipher function, CIPH, of an approved 128-bit block
	 * cipher;<br>
	 * Key, K, for the block cipher;<br>
	 * Base, radix;<br>
	 * Range of supported message lengths, [minlen..maxlen].
	 * <p>
	 * Inputs:<br>
	 * Numeral string, X, in base radix of length n, such that n is in the range
	 * [minlen..maxlen];<br>
	 * Tweak bit string, T, such that LEN(T) = 64.<br>
	 * <p>
	 * Output:<br>
	 * Numeral string, Y, such that LEN(Y) = n.
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            8-byte tweak array.
	 * @param X
	 *            The plaintext numeral string.
	 * @return The ciphertext numeral string of the same length and radix.
	 * @throws NullPointerException
	 *             If any of the arguments are null.
	 * @throws InvalidKeyException
	 *             If K is not a valid AES key.
	 * @throws IllegalArgumentException
	 *             If T is not 8 bytes long; the length of X is not within the
	 *             range [minlen..maxlen]; or any value X[i] is not in the range
	 *             [0..radix].
	 */
	public int[] decrypt(SecretKey K, byte[] T, int[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be an AES key");
		if (!K.getFormat().equals("RAW"))
			throw new InvalidKeyException("K must be in RAW format");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null");
		if (T.length != 8)
			throw new IllegalArgumentException("T must be an array of 8 bytes: " + T.length);

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < minlen || X.length > maxlen)
			throw new IllegalArgumentException(
					"The length of X is not within the permitted range of " + minlen + ".." + maxlen + ": " + X.length);

		if (Constants.CONFORMANCE_OUTPUT) {
			System.out.println("FF3.Decrypt()\n");
			System.out.println("X is " + intArrayToString(X));
			System.out.println("Tweak is " + byteArrayToHexString(T) + "\n");
		}

		// value of n for readability
		int n = X.length;

		// value of REVB(K) for readability
		SecretKeySpec revK = new SecretKeySpec(revb(K.getEncoded()), "AES");

		// 1. Let u = ceiling(n/2); v = n – u.
		int u = ceiling(n / 2.0);
		int v = n - u;
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 1\n\tu is <" + u + ">, and v is <" + v + ">");

		// 2. Let A = X[1..u]; B = X[u + 1..n].
		int[] A = Arrays.copyOfRange(X, 0, u);
		int[] B = Arrays.copyOfRange(X, u, n);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 2\n\tA is " + intArrayToString(A) + "\n\tB is " + intArrayToString(B));

		// 3. Let T_L = T[0..31] and T_R = T[32..63]
		byte[] T_L = Arrays.copyOfRange(T, 0, 4);
		byte[] T_R = Arrays.copyOfRange(T, 4, 8);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println(
					"Step 3\n\tT_L is " + byteArrayToHexString(T_L) + "\n\tT_R is " + byteArrayToHexString(T_R) + "\n");

		// 4. For i from 7 to 0:
		for (int i = 7; i >= 0; i--) {
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("Round #" + i);

			// i. If i is even, let m = u and W = T_R ,
			// else let m = v and W =T_L .
			int m = i % 2 == 0 ? u : v;
			byte[] W = i % 2 == 0 ? T_R : T_L;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.i\n\t\tm is <" + m + ">\n\t\tW is " + byteArrayToHexString(W));

			// ii. Let P = W xor [i]^4 || [NUMradix (REV(A))]^12 .
			byte[] P = concatenate(xor(W, bytestring(i, 4)), bytestring(num(rev(A), radix), 12));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.ii\n\t\tP is " + unsignedByteArrayToString(P));

			// iii Let S = REVB(CIPH REVB(K) REVB(P)).
			byte[] S = revb(mCiphers.ciph(revK, revb(P)));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.iii\n\t\tS is " + byteArrayToHexString(S));

			// iv. Let y = NUM(S).
			BigInteger y = num(S);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.iv\n\t\ty is " + y);

			// v. Let c = (NUMradix (REV(B))–y) mod radix m .
			BigInteger c = mod(num(rev(B), radix).subtract(y), BigInteger.valueOf(radix).pow(m));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.v\n\t\tc is " + c);

			// vi. Let C = REV(STR m radix (c)).
			int[] C = rev(str(c, radix, m));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.vi\n\t\tC is " + intArrayToString(C));

			// vii. Let B = A.
			B = A;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.vii\n\t\tB is " + intArrayToString(B));

			// viii. Let A = C.
			A = C;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 4.viii\n\t\tA is " + intArrayToString(A));
		}
		// 5. Return A || B.
		int[] AB = concatenate(A, B);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 5\n\tA || B is " + intArrayToString(AB));
		return AB;
	}
}
