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

/**
 * Implementation of the FF1 method for format-preserving encryption defined in
 * NIST SP 800-38G.
 * <p>
 * To use this class, construct an instance and call the encrypt() and/or
 * decrypt() methods.
 * 
 * @author Kai Johnson
 *
 */
public class FF1 {

	/**
	 * The radix for symbols to be processed by FF1.
	 */
	private final int radix;

	/**
	 * The maximum length of a tweak in bytes.
	 */
	private final int maxTlen;

	/**
	 * Ciphers instance to provide common cipher functions.
	 */
	private final Ciphers mCiphers;

	/**
	 * Construct a new FF1 instance with a given radix and maximum tweak length.
	 * 
	 * @param radix
	 *            The radix for symbols to be processed by this instance.
	 * @param maxTlen
	 *            The maximum length of tweaks accepted by this instance.
	 * @throws IllegalArgumentException
	 *             If radix is not in the range
	 *             [{@value org.fpe4j.Constants#MINRADIX}..{@value org.fpe4j.Constants#MAXRADIX}];
	 *             or if maxTlen is not in the range
	 *             [0..{@value org.fpe4j.Constants#MAXLEN}].
	 */
	FF1(int radix, int maxTlen) {
		// validate radix
		if (radix < Constants.MINRADIX || radix > Constants.MAXRADIX)
			throw new IllegalArgumentException(
					"Radix must be in the range [" + Constants.MINRADIX + ".." + Constants.MAXRADIX + "]: " + radix);

		// validate maxTlen
		if (maxTlen < 0 || maxTlen > Constants.MAXLEN)
			throw new IllegalArgumentException(
					"maxTlen must be in the range [0.." + Constants.MAXLEN + "]: " + maxTlen);

		this.radix = radix;
		this.maxTlen = maxTlen;
		mCiphers = new Ciphers();
	}

	/**
	 * NIST SP 800-38G Algorithm 7: FF1.Encrypt(K, T, X) - Encrypt a plaintext
	 * string of numerals and produce a ciphertext string of numerals of the
	 * same length and radix.
	 * <p>
	 * Prerequisites:<br>
	 * Designated cipher function, CIPH, of an approved 128-bit block
	 * cipher;<br>
	 * Key, K, for the block cipher; <br>
	 * Base, radix;<br>
	 * Range of supported message lengths, [minlen..maxlen];<br>
	 * Maximum byte length for tweaks, maxTlen.<br>
	 * <p>
	 * Inputs:<br>
	 * Numeral string, X, in base radix of length n, such that n is in the range
	 * [minlen..maxlen];<br>
	 * Tweak T, a byte string of byte length t, such that t is in the range
	 * [0..maxTlen].<br>
	 * <p>
	 * Output:<br>
	 * Numeral string, Y, such that LEN(Y) = n.
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            The tweak with length in the range [0..maxTlen].
	 * @param X
	 *            The plaintext numeral string.
	 * @return The ciphertext numeral string of the same length and radix.
	 * @throws NullPointerException
	 *             If any of the arguments are null.
	 * @throws IllegalArgumentException
	 *             If the length of T is not within the range of [0..maxTlen];
	 *             the length of X is not within the range
	 *             [{@value org.fpe4j.Constants#MINLEN}..{@value org.fpe4j.Constants#MAXLEN}];
	 *             radix<sup>X.length</sup> is less than 100; or any value X[i]
	 *             is not in the range [0..radix].
	 * @throws InvalidKeyException
	 *             If K is not a valid AES key.
	 */
	public int[] encrypt(SecretKey K, byte[] T, int[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be an AES key");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null");
		if (T.length > maxTlen)
			throw new IllegalArgumentException(
					"The length of T is not within the permitted range of 1.." + maxTlen + ": " + T.length);

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < Constants.MINLEN || X.length > Constants.MAXLEN)
			throw new IllegalArgumentException("The length of X is not within the permitted range of "
					+ Constants.MINLEN + ".." + Constants.MAXLEN + ": " + X.length);
		if (Math.pow(radix, X.length) < 100)
			throw new IllegalArgumentException(
					"The length of X must be such that radix ^ length > 100 (radix ^ length ="
							+ Math.pow(radix, X.length));

		if (Constants.CONFORMANCE_OUTPUT) {
			System.out.println("FF1.Encrypt()\n");
			System.out.println("X is " + intArrayToString(X));
			System.out.println("Tweak is " + (T.length > 0 ? byteArrayToHexString(T) : "empty") + "\n");
		}

		// values of n and t for readability
		int n = X.length;
		int t = T.length;

		// 1. Let u = floor(n/2); v = n – u.
		int u = floor(n / 2.0);
		int v = n - u;
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 1\n\tu is " + u + ", v is " + v);

		// 2. Let A = X[1..u]; B = X[u + 1..n].
		int[] A = Arrays.copyOfRange(X, 0, u);
		int[] B = Arrays.copyOfRange(X, u, n);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 2\n\tA is " + intArrayToString(A) + "\n\tB is " + intArrayToString(B));

		// 3. Let b = ceiling(ceiling(v * LOG(radix))/8).
		int b = ceiling(ceiling(v * log2(radix)) / 8.0);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 3\n\tb is " + b);

		// 4. Let d = 4 * ceiling(b/4) + 4.
		int d = 4 * ceiling(b / 4.0) + 4;
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 4\n\td is " + d);

		// 5. Let P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 || [u mod
		// 256]^1 || [n]^4 || [t]^4 .
		byte[] tbr = bytestring(radix, 3);
		byte[] fbn = bytestring(n, 4);
		byte[] fbt = bytestring(t, 4);
		byte[] P = { (byte) 0x01, (byte) 0x02, (byte) 0x01, tbr[0], tbr[1], tbr[2], (byte) 0x0A,
				(byte) (mod(u, 256) & 0xFF), fbn[0], fbn[1], fbn[2], fbn[3], fbt[0], fbt[1], fbt[2], fbt[3] };
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 5\n\tP is " + unsignedByteArrayToString(P) + "\n");

		// 6. For i from 0 to 9:
		for (int i = 0; i < 10; i++) {
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("Round #" + i);

			// i. Let Q = T || [0]^(-t-b-1) mod 16 || [i]^1 || [NUMradix (B)]^b
			byte[] Q = concatenate(T, bytestring(0, mod(-t - b - 1, 16)));
			Q = concatenate(Q, bytestring(i, 1));
			Q = concatenate(Q, bytestring(num(B, radix), b));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.i.\n\t\tQ is " + unsignedByteArrayToString(Q));

			// ii. Let R = PRF(P || Q).
			byte[] R = mCiphers.prf(K, concatenate(P, Q));
			// byte[] R = concatenate(prf(K, concatenate(P, Q)), P);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.ii.\n\t\tR is " + unsignedByteArrayToString(R));
			/*
			 * Pseudocode in NIST SP 800-38G shows:
			 * 
			 * R = PRF(P || Q)
			 * 
			 * However, the sample data shows values that match:
			 * 
			 * R = PRF(P || Q) || P
			 * 
			 * The results are not different for the sample data sets, but step
			 * 6. iii. below would fail for inputs where d > 16 if we produced
			 * values of R that match the sample data.
			 */

			// iii. Let S be the first d bytes of the following string of
			// ceiling(d/16) blocks: R || CIPH K (R xor [1]^16 ) || CIPH K (R
			// xor [2]^16 ) … CIPH K (R xor [ceiling(d/16)–1]^16 ).
			byte[] S = R;
			for (int j = 1; j <= ceiling(d / 16.0) - 1; j++) {
				S = concatenate(S, mCiphers.ciph(K, xor(R, bytestring(j, 16))));
			}
			S = Arrays.copyOf(S, d);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.iii.\n\t\tS is " + byteArrayToHexString(S));

			// iv. Let y = NUM(S).
			BigInteger y = num(S);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.iv.\n\t\ty is " + y);

			// v. If i is even, let m = u; else, let m = v.
			int m = i % 2 == 0 ? u : v;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.v.\n\t\tm is " + m);

			// vi. Let c = (NUMradix (A)+y) mod radix^m .
			BigInteger c = mod(num(A, radix).add(y), BigInteger.valueOf(radix).pow(m));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.vi.\n\t\tc is " + c);

			// vii. Let C = STR m radix (c).
			int[] C = str(c, radix, m);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.vii.\n\t\tC is " + intArrayToString(C));

			// viii. Let A = B.
			A = B;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.viii.\n\t\tA is " + intArrayToString(A));

			// ix. Let B = C.
			B = C;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.ix.\n\t\tB is " + intArrayToString(B));
		}
		// 7. Return A || B.
		int[] AB = concatenate(A, B);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 7.\n\tA || B is " + intArrayToString(AB) + "\n");
		return AB;
	}

	/**
	 * NIST SP 800-38G Algorithm 8: FF1.Decrypt(K, T, X) - Decrypt a ciphertext
	 * string of numerals and produce a plaintext string of numerals of the same
	 * length and radix.
	 * <p>
	 * Prerequisites: <br>
	 * Designated cipher function, CIPH, of an approved 128-bit block
	 * cipher;<br>
	 * Key, K, for the block cipher;<br>
	 * Base, radix;<br>
	 * Range of supported message lengths, [minlen..maxlen];<br>
	 * Maximum byte length for tweaks, maxTlen.
	 * <p>
	 * Inputs:<br>
	 * Numeral string, X, in base radix of length n, such that n is in the range
	 * [minlen..maxlen];<br>
	 * Tweak T, a byte string of byte length t, such that t is in the range
	 * [0..maxTlen].
	 * <p>
	 * Output:<br>
	 * Numeral string, Y, such that LEN(Y) = n.
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            The tweak with length in the range [0..maxTlen].
	 * @param X
	 *            The ciphertext numeral string.
	 * @return The plaintext numeral string of the same length and radix.
	 * @throws NullPointerException
	 *             If any of the arguments are null.
	 * @throws IllegalArgumentException
	 *             If the length of T is not within the range of [0..maxTlen];
	 *             the length of X is not within the range
	 *             [{@value org.fpe4j.Constants#MINLEN}..{@value org.fpe4j.Constants#MAXLEN}];
	 *             radix<sup>X.length</sup> is less than 100; or any value X[i]
	 *             is not in the range [0..radix].
	 * @throws InvalidKeyException
	 *             If K is not a valid AES key.
	 */
	public int[] decrypt(SecretKey K, byte[] T, int[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be an AES key");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null");
		// alternatively, we could initialize T to an empty array in this case

		if (T.length > maxTlen)
			throw new IllegalArgumentException(
					"The length of T is not within the permitted range of 1.." + maxTlen + ": " + T.length);

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < Constants.MINLEN || X.length > Constants.MAXLEN)
			throw new IllegalArgumentException("The length of X is not within the permitted range of "
					+ Constants.MINLEN + ".." + Constants.MAXLEN + ": " + X.length);
		if (Math.pow(radix, X.length) < 100)
			throw new IllegalArgumentException("The length of X must be such that radix ^ length > 100");

		if (Constants.CONFORMANCE_OUTPUT) {
			System.out.println("FF1.Decrypt()\n");
			System.out.println("X is " + intArrayToString(X));
			System.out.println("Tweak is " + (T.length > 0 ? byteArrayToHexString(T) : "empty") + "\n");
		}

		int n = X.length;
		int t = T.length;

		// 1. Let u = floor(n/2); v = n – u.
		int u = floor(n / 2.0);
		int v = n - u;
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 1\n\tu is " + u + ", v is " + v);

		// 2. Let A = X[1..u]; B = X[u+1..n].
		int[] A = Arrays.copyOfRange(X, 0, u);
		int[] B = Arrays.copyOfRange(X, u, n);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 2\n\tA is " + intArrayToString(A) + "\n\tB is " + intArrayToString(B));

		// 3. Let b = ceiling(ceiling(v * LOG(radix))/8).
		int b = ceiling(ceiling(v * log2(radix)) / 8.0);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 3\n\tb is " + b);

		// 4. Let d = 4 * ceiling(b/4)+4
		int d = 4 * ceiling(b / 4.0) + 4;
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 4\n\td is " + d);

		// 5. Let P = [1] 1 || [2] 1 || [1] 1 || [radix] 3 || [10] 1 ||[u mod
		// 256] 1 || [n] 4 || [t] 4 .
		byte[] tbr = bytestring(radix, 3);
		byte[] fbn = bytestring(n, 4);
		byte[] fbt = bytestring(t, 4);
		byte[] P = { (byte) 0x01, (byte) 0x02, (byte) 0x01, tbr[0], tbr[1], tbr[2], (byte) 0x0A,
				(byte) (mod(u, 256) & 0xFF), fbn[0], fbn[1], fbn[2], fbn[3], fbt[0], fbt[1], fbt[2], fbt[3] };
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 5\n\tP is " + unsignedByteArrayToString(P) + "\n");

		// 6. For i from 9 to 0:
		for (int i = 9; i >= 0; i--) {
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("Round #" + i);

			// i. Let Q = T || [0] (-t-b-1) mod 16 || [i] 1 || [NUMradix (A)] b
			byte[] Q = concatenate(T, bytestring(0, mod(-t - b - 1, 16)));
			Q = concatenate(Q, bytestring(i, 1));
			Q = concatenate(Q, bytestring(num(A, radix), b));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.i.\n\t\tQ is " + unsignedByteArrayToString(Q));

			// ii. Let R = PRF(P || Q).
			byte[] R = mCiphers.prf2(K, concatenate(P, Q));
			// byte[] R = concatenate(mCiphers.prf2(K, concatenate(P, Q)), P);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.ii.\n\t\tR is " + unsignedByteArrayToString(R));
			/*
			 * Psuedocode in NIST SP 800-38G shows:
			 * 
			 * R = PRF(P || Q)
			 * 
			 * However, the sample data shows values that match:
			 * 
			 * R = PRF(P || Q) || P
			 * 
			 * The results are not different for the sample data sets, but step
			 * 6. iii. below would fail for inputs where d > 16 if we produced
			 * values of R that match the sample data.
			 *
			 */

			// iii. Let S be the string of the first d bytes of the following
			// string of ceiling (d/16) blocks: R || CIPH K (R xor [1] 16 ) ||
			// CIPH K (R xor [2] 16 ) … CIPH K (R xor [ceiling(d/16) – 1] 16 ).
			byte[] S = R;
			for (int j = 1; j <= ceiling(d / 16.0) - 1; j++) {
				S = concatenate(S, mCiphers.ciph(K, xor(R, bytestring(j, 16))));
			}
			S = Arrays.copyOf(S, d);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.iii.\n\t\tS is " + byteArrayToHexString(S));

			// iv. Let y = NUM(S).
			BigInteger y = num(S);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.iv.\n\t\ty is " + y);

			// v. If i is even, let m = u; else, let m = v.
			int m = i % 2 == 0 ? u : v;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.v.\n\t\tm is " + m);

			// vi. Let c = (NUMradix (B)–y) mod radix m .
			BigInteger c = mod(num(B, radix).subtract(y), BigInteger.valueOf(radix).pow(m));
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.vi.\n\t\tc is " + c);

			// vii. Let C = STR m radix (c).
			int[] C = str(c, radix, m);
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.vii.\n\t\tC is " + intArrayToString(C));

			// viii. Let B = A.
			B = A;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.viii.\n\t\tB is " + intArrayToString(B));

			// ix. Let A = C.
			A = C;
			if (Constants.CONFORMANCE_OUTPUT)
				System.out.println("\tStep 6.ix.\n\t\tA is " + intArrayToString(A));
		}

		// 7. Return A || B.
		int[] AB = concatenate(A, B);
		if (Constants.CONFORMANCE_OUTPUT)
			System.out.println("Step 7.\n\tA || B is " + intArrayToString(AB) + "\n");
		return AB;
	}
}
