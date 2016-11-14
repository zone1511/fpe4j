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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Common cipher functions for FF1 and FF3 based on AES.
 * 
 * @author Kai Johnson
 *
 */
class Ciphers {

	/**
	 * Instance of the AES cipher in ECB mode with no padding.
	 */
	private Cipher mAesEcbCipher;

	/**
	 * Instance of the AES cipher in CBC mode with no padding.
	 */
	private Cipher mAesCbcCipher;

	/**
	 * Constructs a Ciphers instance with the required AES ciphers.
	 */
	public Ciphers() {
		try {
			mAesEcbCipher = Cipher.getInstance("AES/ECB/NoPadding");
			mAesCbcCipher = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// this could happen if the JRE doesn't have the ciphers
			throw new RuntimeException(e);
		}
	}

	/**
	 * NIST SP 800-38G Algorithm 6: PRF(X) - Applies the pseudorandom function
	 * to the input using the supplied key.
	 * <p>
	 * Prerequisites:<br>
	 * Designated cipher function, CIPH, of an approved 128-bit block
	 * cipher;<br>
	 * Key, K, for the block cipher.
	 * <p>
	 * Input:<br>
	 * Block string, X.
	 * <p>
	 * Output:<br>
	 * Block, Y.
	 * 
	 * @param K
	 *            The AES key for the cipher function.
	 * @param X
	 *            The block string input.
	 * @return The output of the function PRF applied to the block X; PRF is
	 *         defined in terms of a given designated cipher function.
	 * @throws InvalidKeyException
	 *             If the key is not a valid AES key.
	 */
	public byte[] prf(SecretKey K, byte[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must contain an AES key");

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < 1 || X.length > Constants.MAXLEN)
			throw new IllegalArgumentException(
					"The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.length);

		// 1. Let m = LEN(X)/128.
		// i.e. BYTELEN(X)/16
		int m = X.length / 16;

		// 2. Let X[1], …, X[m] be the blocks for which X = X[1] || … || X[m].
		// we extract the blocks inside the for loop

		// 3. Let Y(0) = bitstring(0,128), and
		byte[] Y = Common.bitstring(false, 128);

		// for j from 1 to m let Y(j) = CIPH(K,Y(j–1) xor X[j]).
		for (int j = 0; j < m; j++) {
			byte[] Xj = Arrays.copyOfRange(X, j * 16, j * 16 + 16);
			try {
				mAesEcbCipher.init(Cipher.ENCRYPT_MODE, K);

				Y = mAesEcbCipher.doFinal(Common.xor(Y, Xj));

			} catch (IllegalBlockSizeException | BadPaddingException e) {
				// these would be programming errors so convert to an unchecked
				// exception
				throw new RuntimeException(e);
			}
		}

		// 4. Return Y(m).
		return Y;
	}

	/**
	 * Equivalent implementation of the PRF(X) algorithm using the AES CBC
	 * cipher with a zero initialization vector.
	 * <p>
	 * The PRF(X) algorithm is an implementation of CBC mode encryption with a
	 * zero initialization vector. PRF(X) then extracts the last block as the
	 * result. Instead of implementing CBC by hand, this method uses the Java
	 * libraries to perform the same operation, and to demonstrate the
	 * equivalence of the methods.
	 * 
	 * @param K
	 *            The AES key for the cipher function
	 * @param X
	 *            The block string input
	 * @return The output of the function PRF applied to the block X; PRF is
	 *         defined in terms of a given designated cipher function.
	 * @throws InvalidKeyException
	 *             If the key is not a valid AES key.
	 */
	public byte[] prf2(SecretKey K, byte[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be an AES key");

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < 1 || X.length > Constants.MAXLEN)
			throw new IllegalArgumentException(
					"The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.length);

		byte[] Z;

		try {
			byte[] Y = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
					(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
					(byte) 0x00, (byte) 0x00 };

			mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, new IvParameterSpec(Y));

			Z = mAesCbcCipher.doFinal(X);

		} catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			// these would be programming errors so convert to an unchecked
			// exception
			throw new RuntimeException(e);
		}

		return Arrays.copyOfRange(Z, Z.length - 16, Z.length);
	}

	/**
	 * Encrypts the input using the AES block cipher in ECB mode using the
	 * specified key.
	 * <p>
	 * Although the ECB mode of operation is not explicitly mentioned in NIST SP
	 * 800-38G, it is implied by the use of the CIPH(X) function in FF1 and FF3.
	 * <p>
	 * To quote NIST SP 800-38G, "For both of the modes, the underlying block
	 * cipher shall be approved, and the block size shall be 128 bits.
	 * Currently, the AES block cipher, with key lengths of 128, 192, or 256
	 * bits, is the only block cipher that fits this profile."
	 * 
	 * @param K
	 *            The AES key for the cipher function
	 * @param X
	 *            The block string input
	 * @return The output of the cipher function applied to the block X.
	 * @throws InvalidKeyException
	 *             If the key is not a valid AES key.
	 */
	public byte[] ciph(SecretKey K, byte[] X) throws InvalidKeyException {
		// validate K
		if (K == null)
			throw new NullPointerException("K must not be null");
		if (!K.getAlgorithm().equals("AES"))
			throw new InvalidKeyException("K must be an AES key");

		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < 1 || X.length > Constants.MAXLEN)
			throw new IllegalArgumentException(
					"The length of X is not within the permitted range of 1.." + Constants.MAXLEN + ": " + X.length);

		byte[] cipherText;
		try {

			mAesEcbCipher.init(Cipher.ENCRYPT_MODE, K);

			cipherText = mAesEcbCipher.doFinal(X);

		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// these would be programming errors so convert to an unchecked
			// exception
			throw new RuntimeException(e);
		}

		return cipherText;
	}
}
