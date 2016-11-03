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

import static org.fpe4j.Common.bytestring;
import static org.fpe4j.Common.floor;

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

import org.fpe4j.FFX.ArithmeticFunction;
import org.fpe4j.FFX.FFXParameters;
import org.fpe4j.FFX.FeistelMethod;
import org.fpe4j.FFX.RoundCounter;
import org.fpe4j.FFX.RoundFunction;
import org.fpe4j.FFX.SplitFunction;

/**
 * FFX parameter set for the A2 algorithm defined in <a href=
 * "http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.1736&rep=rep1&type=pdf">The
 * FFX Mode of Operation for Format-Preserving Encryption</a>, by Mihir Bellare,
 * Phillip Rogaway, and Terence Spies.
 *
 * @author Kai Johnson
 *
 */
public class A2Parameters implements FFXParameters {

	/**
	 * Instance of the AES cipher in CBC mode with no padding.
	 */
	private Cipher mAesCbcCipher;

	/**
	 * Zero initialization vector for AEC CBC
	 */
	private IvParameterSpec mAesCbcIv;

	/**
	 * Split function for A2
	 */
	private final FFX.SplitFunction a2Splitter = new FFX.SplitFunction() {

		@Override
		public int split(int n) {
			return floor(n / 2.0);
		}
	};

	/**
	 * Function to determine the number of Feistel rounds for A2
	 */
	private final FFX.RoundCounter a2RoundCounter = new FFX.RoundCounter() {

		@Override
		public int rnds(int n) {
			if (n <= 7 || n >= 129)
				throw new IllegalArgumentException("n must be in the range [8..128]: " + n);
			else if (n <= 9)
				return 36;
			else if (n <= 13)
				return 30;
			else if (n <= 19)
				return 24;
			else if (n <= 31)
				return 18;
			else /* if (n <= 128) */
				return 12;
		}
	};

	/**
	 * Round function F for A2
	 */
	private final FFX.RoundFunction a2Round = new FFX.RoundFunction() {

		@Override
		public int[] F(SecretKey K, int n, byte[] T, int i, int[] B) throws InvalidKeyException {
			// algorithm F K(n, T, i, B)

			// vers <- 1; t <- |T|8
			int t = T.length;

			// P <- [vers]^2 || [method]^1 || [addition]^1 || [radix]^1 || [n]^1
			// || [split(n)]^1 || [rnds(n)]^1 || [t]^8
			byte[] obn = bytestring(n, 1);
			byte[] obs = bytestring(a2Splitter.split(n), 1);
			byte[] obr = bytestring(a2RoundCounter.rnds(n), 1);
			byte[] ebt = bytestring(t, 8);
			byte[] P = { 0, 1, 2, 0, 2, obn[0], obs[0], obr[0], ebt[7], ebt[6], ebt[5], ebt[4], ebt[3], ebt[2], ebt[1],
					ebt[0] };

			// Q <- T || [0]^(-t-9 mod 16) || [i]^1 || 0^(64-|B|) || B
			byte[] Q = T;
			Q = Common.concatenate(Q, bytestring(0, Common.mod(-t - 9, 16)));
			Q = Common.concatenate(Q, bytestring(i, 1));
			/*
			 * Note that the last two operands form a 64-bit string of the value
			 * of B padded with leading zeros. Since the maximum length of the
			 * input (n) is 128, |B| is always <= 64. To conform with the FFX
			 * specification, B is an array of integers, albeit with values of
			 * only 1 or 0. Rather than generate odd-length bit strings for the
			 * padding and B, we convert B directly to a string of 8 bytes.
			 */
			Q = Common.concatenate(Q, Common.bytestring(Common.num(B, getRadix()), 8));

			// Y <- CBC-MAC K(P || Q)
			byte[] Y;

			try {
				mAesCbcCipher.init(Cipher.ENCRYPT_MODE, K, mAesCbcIv);
				Y = mAesCbcCipher.doFinal(Common.concatenate(P, Q));
				Y = Arrays.copyOfRange(Y, Y.length - 16, Y.length);
			} catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
				// these would be programming errors so convert to an unchecked
				// exception
				throw new RuntimeException(e);
			}

			// if even (i) then m <- split(n) else m <- n-split(n)
			int m = i % 2 == 0 ? a2Splitter.split(n) : n - a2Splitter.split(n);

			// return Y [129 - m .. 128]
			int[] Z = Common.str(Common.num(Y), 2, 128);
			return Arrays.copyOfRange(Z, 128 - m, 128);
		}

		@Override
		public boolean validKey(SecretKey K) {
			// validate K
			if (K == null)
				return false;
			if (!K.getAlgorithm().equals("AES"))
				return false;
			return true;
		}

	};

	/**
	 * Construct a new A2Parameters instance.
	 */
	public A2Parameters() {
		try {
			mAesCbcCipher = Cipher.getInstance("AES/CBC/NoPadding");
			mAesCbcIv = new IvParameterSpec(new byte[16]);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// this could happen if the JRE doesn't have the AES-CBC cipher
			throw new RuntimeException(e);
		}
	}

	@Override
	public int getRadix() {
		return 2;
	}

	@Override
	public int getMinLen() {
		return 8;
	}

	@Override
	public int getMaxLen() {
		return 128;
	}

	@Override
	public int getMinTLen() {
		return 0;
	}

	@Override
	public int getMaxTLen() {
		return Integer.MAX_VALUE;
	}

	@Override
	public ArithmeticFunction getArithmeticFunction() {
		return FFX.getCharwiseArithmeticFunction(getRadix());
	}

	@Override
	public FeistelMethod getFeistelMethod() {
		return FeistelMethod.TWO;
	}

	@Override
	public SplitFunction getSplitter() {
		return a2Splitter;
	}

	@Override
	public RoundCounter getRoundCounter() {
		return a2RoundCounter;
	}

	@Override
	public RoundFunction getRoundFunction() {
		return a2Round;
	}
}
