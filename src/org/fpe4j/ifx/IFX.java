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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Implementation of the experimental IFX algorithm described in ifx-spec.pdf.
 * The IFX algorithm is intended for format-preserving encryption of strings of
 * non-uniform symbols, e.g. mixed digits and letters.
 * <p>
 * To use this class, you must construct an instance, call initialize(int[])
 * with an array of radices to specify the format of the strings to be
 * encrypted, then call the encrypt() and decrypt() methods.
 * <p>
 * This algorithm was developed as a proof of concept for the encoding/decoding
 * process, and the method of splitting non-uniform input strings for Feistel
 * rounds. No assertions are made about the security of the resulting output.
 * Until further cryptanalysis has been performed, this method is NOT
 * RECOMMENDED for use with sensitive data.
 * 
 * @author Kai Johnson
 *
 */
public class IFX {

	/**
	 * Instance of the AES cipher in CBC mode with no padding.
	 */
	private final Cipher mAesCbcCipher;

	/**
	 * Zero initialization vector for AEC CBC
	 */
	private final IvParameterSpec mAesCbcIv;

	/**
	 * Radix of left (most significant) portion of w
	 */
	private final BigInteger mu;

	/**
	 * Radix of right (least significant) portion of w
	 */
	private final BigInteger mv;

	/**
	 * Product of the elements of W
	 */
	private final BigInteger mw;

	/**
	 * Array of radices
	 */
	private final int[] mW;

	/**
	 * Construct a new IFX instance and initialize the instance with a vector of
	 * radices.
	 * <p>
	 * Inputs: <br>
	 * W, an arbitrary length vector of radices, where each radix is an integer
	 * greater than or equal to two
	 * <p>
	 * Outputs: <br>
	 * w, an unconstrained integer<br>
	 * u and v, unconstrained integers such that u × v=w
	 * 
	 * @param W
	 *            array of radices
	 */
	public IFX(int[] W) {
		// validate W
		if (W == null)
			throw new NullPointerException("W must not be null");
		if (W.length < 2)
			throw new IllegalArgumentException("W must have at least two elements: " + W.length);

		// w <- product(W)
		BigInteger w = Functions.product(W);
		BigInteger r = Functions.sqrt(w);

		// validate w
		if (w.compareTo(BigInteger.valueOf(100)) < 0)
			throw new IllegalArgumentException("product(W) must be at least 100: " + w);

		// G <- descending(factors(W))
		List<Integer> G = Functions.factors(W);
		Collections.sort(G, Functions.INTEGER_DESCENDING_COMPARATOR);

		// u <- 1; v <- 1
		BigInteger u = BigInteger.ONE;
		BigInteger v = BigInteger.ONE;

		// For each element g of G
		for (Integer g : G) {
			// If u × g <= floor(sqrt(w)), u <- u × g; else v <- v × g
			if (u.multiply(BigInteger.valueOf(g.intValue())).compareTo(r) <= 0) {
				u = u.multiply(BigInteger.valueOf(g.intValue()));
			} else {
				v = v.multiply(BigInteger.valueOf(g.intValue()));
			}
		}

		// get AES CBC cipher instance
		try {
			mAesCbcIv = new IvParameterSpec(new byte[16]);
			mAesCbcCipher = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// this could happen if the JRE doesn't have the AES-CBC cipher
			throw new RuntimeException(e);
		}

		// initialize instance variables
		mW = W;
		mw = w;
		mu = u;
		mv = v;
	}

	/**
	 * IFX.Decrypt(K,T,Y) Encrypt a plaintext vector using the supplied key and
	 * tweak.
	 * <p>
	 * Prerequisites:<br>
	 * W, an arbitrary length vector of radices supplied to IFX.Initialize<br>
	 * u and v, unconstrained integers such that u × v=product(W)
	 * <p>
	 * Inputs:<br>
	 * K, an AES key<br>
	 * T, a vector of bytes of arbitrary length<br>
	 * Y, a plaintext vector of length(W) integers such that 0 &lt;= Y[i] &lt;
	 * W[i] for all i in 0..length(W)
	 * <p>
	 * Outputs:<br>
	 * X, a ciphertext vector of length(W) integers such that 0 &lt;= X[i] &lt;
	 * W[i] for all i in 0..length(W)
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            The array of bytes to use as a tweak.
	 * @param Y
	 *            The ciphertext array of values with radices corresponding to
	 *            W.
	 * @return The plaintext array of values with radices corresponding to W.
	 * @throws InvalidKeyException
	 *             if K is not a valid AES key
	 */
	public int[] decrypt(SecretKey K, byte[] T, int[] Y) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null.");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be a valid AES key.");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null");

		// validate Y
		if (Y == null)
			throw new NullPointerException("Y must not be null");
		if (Y.length != mW.length)
			throw new IllegalArgumentException("Y must be the same length as W: " + Y.length);

		// y<-num(Y)
		BigInteger y = num(Y);

		// a<-y div v
		BigInteger a = y.divide(mv);

		// b<-y mod v
		BigInteger b = y.mod(mv);

		// r<-rounds(u,v)
		int r = Functions.rounds(mu, mv);

		// R<-bytes(r)
		byte[] R = Functions.bytes(r);

		// U<-bytes(u)
		byte[] U = Functions.bytes(mu);

		// V<-bytes(v)
		byte[] V = Functions.bytes(mv);

		// s<-length(T)+length(U)+length(V)+length(R)
		int s = T.length + U.length + V.length + R.length;

		// S<-bytes(s)
		byte[] S = Functions.bytes(s);

		// O<-R || S ||
		// padding(-length(R)-length(S)-length(T)-length(U)-length(V) mod 16) ||
		// T || U || V
		int o = R.length + S.length + T.length + U.length + V.length;
		o += Functions.mod(-o, 16);
		byte[] O = new byte[o];
		o = 0;
		System.arraycopy(R, 0, O, o, R.length);
		o += R.length;
		System.arraycopy(S, 0, O, o, S.length);
		o += S.length;
		System.arraycopy(Functions.padding(Functions.mod(-s - S.length, 16)), 0, O, o,
				Functions.mod(-s - S.length, 16));
		o += Functions.mod(-s - S.length, 16);
		System.arraycopy(T, 0, O, o, T.length);
		o += T.length;
		System.arraycopy(U, 0, O, o, U.length);
		o += U.length;
		System.arraycopy(V, 0, O, o, V.length);
		o += V.length;

		byte[] P = null;
		try {
			// I<-{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
			mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, mAesCbcIv);

			// P<-ciph(K,I,O)
			P = mAesCbcCipher.doFinal(O);

		} catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
		// P<-P[length(P)-16..length(P)-1]
		P = Arrays.copyOfRange(P, P.length - 16, P.length);
		IvParameterSpec p = new IvParameterSpec(P);

		// For i in r-1..0
		for (int i = r - 1; i >= 0; i--) {
			// If i is even, d<-u ; else d<-v
			BigInteger d = i % 2 == 0 ? mu : mv;

			// c<-b
			BigInteger c = b;

			// b<-a
			b = a;

			// I<-bytes(i)
			byte[] I = Functions.bytes(i);

			// B<-bytes(b)
			byte[] B = Functions.bytes(b);

			// Q<-I || padding(-length(I)-length(B) mod 16) || B
			int q = I.length + Functions.mod(-I.length - B.length, 16) + B.length;
			byte[] Q = new byte[q];
			System.arraycopy(I, 0, Q, 0, I.length);
			System.arraycopy(Functions.padding(Functions.mod(-I.length - B.length, 16)), 0, Q, I.length,
					Functions.mod(-I.length - B.length, 16));
			System.arraycopy(B, 0, Q, Q.length - B.length, B.length);

			// F<-ciph(K,P,Q)
			byte[] F = null;
			try {
				mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, p);
				F = mAesCbcCipher.doFinal(Q);
			} catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}

			// f<-num(F)
			BigInteger f = Functions.integer(F);

			// a<-(c-f) mod d
			a = c.subtract(f).mod(d);
		}

		// x<-a × v + b
		BigInteger x = a.multiply(mv).add(b);

		// X<-str(x)
		int[] X = str(x);

		return X;
	}

	/**
	 * IFX.Encrypt(K,T,X) Encrypt a plaintext vector using the supplied key and
	 * tweak.
	 * <p>
	 * Prerequisites:<br>
	 * W, an arbitrary length vector of radices supplied to IFX.Initialize<br>
	 * u and v, unconstrained integers such that u × v=product(W)
	 * <p>
	 * Inputs:<br>
	 * K, an AES key<br>
	 * T, a vector of bytes of arbitrary length<br>
	 * X, a plaintext vector of length(W) integers such that 0 &lt;= X[i] &lt;
	 * W[i] for all i in 0..length(W)
	 * <p>
	 * Outputs:<br>
	 * Y, a ciphertext vector of length(W) integers such that 0 &lt;= Y[i] &lt;
	 * W[i] for all i in 0..length(W)
	 * 
	 * @param K
	 *            The 128-, 192- or 256-bit AES key.
	 * @param T
	 *            The array of bytes to use as a tweak.
	 * @param X
	 *            The plaintext array of values with radices corresponding to W.
	 * @return The ciphertext array of values with radices corresponding to W.
	 * @throws InvalidKeyException
	 *             if K is not a valid AES key
	 */
	public int[] encrypt(SecretKey K, byte[] T, int[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null.");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be a valid AES key.");

		// validate T
		if (T == null)
			throw new NullPointerException("T must not be null");

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length != mW.length)
			throw new IllegalArgumentException("X must be the same length as W: " + X.length);

		// x<-num(X)
		BigInteger x = num(X);

		// a<-x div v
		BigInteger a = x.divide(mv);

		// b<-x mod v
		BigInteger b = x.mod(mv);

		// r<-rounds(u,v)
		int r = Functions.rounds(mu, mv);

		// R<-bytes(r)
		byte[] R = Functions.bytes(r);

		// U<-bytes(u)
		byte[] U = Functions.bytes(mu);

		// V<-bytes(v)
		byte[] V = Functions.bytes(mv);

		// s<-length(T)+length(U)+length(V)+length(R)
		int s = T.length + U.length + V.length + R.length;

		// S<-bytes(s)
		byte[] S = Functions.bytes(s);

		// O<-R || S ||
		// padding(-length(R)-length(S)-length(T)-length(U)-length(V) mod 16) ||
		// T || U || V
		int o = R.length + S.length + T.length + U.length + V.length;
		o += Functions.mod(-o, 16);
		byte[] O = new byte[o];
		o = 0;
		System.arraycopy(R, 0, O, o, R.length);
		o += R.length;
		System.arraycopy(S, 0, O, o, S.length);
		o += S.length;
		System.arraycopy(Functions.padding(Functions.mod(-s - S.length, 16)), 0, O, o,
				Functions.mod(-s - S.length, 16));
		o += Functions.mod(-s - S.length, 16);
		System.arraycopy(T, 0, O, o, T.length);
		o += T.length;
		System.arraycopy(U, 0, O, o, U.length);
		o += U.length;
		System.arraycopy(V, 0, O, o, V.length);
		o += V.length;

		byte[] P = null;
		try {
			// I<-{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
			mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, mAesCbcIv);

			// P<-ciph(K,I,O)
			P = mAesCbcCipher.doFinal(O);

		} catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}

		// P<-P[length(P)-16..length(P)-1]
		P = Arrays.copyOfRange(P, P.length - 16, P.length);
		IvParameterSpec p = new IvParameterSpec(P);

		// For i in 0..r-1
		for (int i = 0; i < r; i++) {
			// If i is even, d<-u ; else d<-v
			BigInteger d = i % 2 == 0 ? mu : mv;

			// I<-bytes(i)
			byte[] I = Functions.bytes(i);

			// B<-bytes(b)
			byte[] B = Functions.bytes(b);

			// Q<-I || padding(-length(I)-length(B) mod 16) || B
			int q = I.length + Functions.mod(-I.length - B.length, 16) + B.length;
			byte[] Q = new byte[q];
			System.arraycopy(I, 0, Q, 0, I.length);
			System.arraycopy(Functions.padding(Functions.mod(-I.length - B.length, 16)), 0, Q, I.length,
					Functions.mod(-I.length - B.length, 16));
			System.arraycopy(B, 0, Q, Q.length - B.length, B.length);

			// F<-ciph(K,P,Q)
			byte[] F = null;
			try {
				mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, p);
				F = mAesCbcCipher.doFinal(Q);
			} catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}

			// f<-num(F)
			BigInteger f = Functions.integer(F);

			// c<-(a+f) mod d
			BigInteger c = a.add(f).mod(d);

			// a<-b
			a = b;

			// b<-c
			b = c;
		}
		// y<-a × v + b
		BigInteger y = a.multiply(mv).add(b);

		// Y<-str(y)
		int[] Y = str(y);

		return Y;
	}

	/**
	 * Accessor for the value of u during testing.
	 * 
	 * @return u
	 */
	BigInteger getU() {
		return mu;
	}

	/**
	 * Accessor for the value of v during testing.
	 * 
	 * @return v
	 */
	BigInteger getV() {
		return mv;
	}

	/**
	 * Accessor for the value of w during testing.
	 * 
	 * @return w
	 */
	BigInteger getW() {
		return mw;
	}

	/**
	 * Unconstrained integer representation of a vector of integer values.
	 * <p>
	 * Prerequisites:<br>
	 * W, an arbitrary length vector of radices supplied to IFX.Initialize
	 * <p>
	 * Inputs:<br>
	 * X, a vector of length(W) integers such that 0 &lt;= X[i] &lt; W[i] for
	 * all i in 0..length(W)
	 * <p>
	 * Outputs:<br>
	 * y, an unconstrained integer
	 * 
	 * @param X
	 *            an array of integers of the same length as the array used to
	 *            initialize this IFX instance
	 * @return an integer value representing the values in X
	 */
	BigInteger num(int[] X) {
		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length != mW.length)
			throw new IllegalArgumentException("X must be the same length as W: " + X.length);

		// y<-0
		BigInteger y = BigInteger.ZERO;

		// For each i in 0..length(X)-1
		for (int i = 0; i < X.length; i++) {
			// validate X[i]
			if (X[i] < 0 || X[i] > mW[i])
				throw new IllegalArgumentException("X[" + i + "] must be in the range 0.." + mW[i] + ": " + X[i]);

			// y<-y × W[i] + X[i]
			y = y.multiply(BigInteger.valueOf(mW[i])).add(BigInteger.valueOf(X[i]));
		}

		return y;
	}

	/**
	 * str(y) Representation an unconstrained integer as a vector of integer
	 * values.
	 * <p>
	 * Prerequisites:<br>
	 * W, an arbitrary length vector of radices supplied to IFX.Initialize
	 * <p>
	 * Input: <br>
	 * y, an unconstrained integer
	 * <p>
	 * Output:<br>
	 * Y, a vector of length(W) integers such that 0 &lt;= Y[i] &lt; W[i] for
	 * all i in 0..length(W)
	 * 
	 * @param y
	 *            an integer value in the range 0..product(W)
	 * @return an array of integers corresponding to the value of y and the
	 *         radices W
	 */
	int[] str(BigInteger y) {
		// validate y
		if (y == null)
			throw new NullPointerException("y must not be null");
		if (y.signum() < 0)
			throw new IllegalArgumentException("y must be nonnegative: " + y);
		if (y.compareTo(mw) >= 0)
			throw new IllegalArgumentException("y must be less than " + mw + ": " + y);

		// Y<-{...},where the length of Y is the same as the length of W
		int[] Y = new int[mW.length];

		// For i in length(W)-1..0
		for (int i = mW.length - 1; i >= 0; i--) {
			// Y[i]<-y mod W[i]
			Y[i] = y.mod(BigInteger.valueOf(mW[i])).intValue();

			// y<-y div W[i]
			y = y.divide(BigInteger.valueOf(mW[i]));
		}

		return Y;
	}
}
