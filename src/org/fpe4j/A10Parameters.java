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

import java.math.BigInteger;
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
 * FFX parameter set for the A10 algorithm defined in <a href=
 * "http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.1736&rep=rep1&type=pdf">The
 * FFX Mode of Operation for Format-Preserving Encryption</a>, by Mihir Bellare,
 * Phillip Rogaway, and Terence Spies.
 *
 * @author Kai Johnson
 *
 */
public class A10Parameters implements FFXParameters {

	/**
	 * Instance of the AES cipher in CBC mode with no padding.
	 */
	private Cipher mAesCbcCipher;

	/**
	 * Zero initialization vector for AEC CBC
	 */
	private IvParameterSpec mAesCbcIv;

	/**
	 * Split function for A10
	 */
	private final FFX.SplitFunction a10Splitter = new FFX.SplitFunction() {

		@Override
		public int split(int n) {
			return floor(n / 2.0);
		}
	};

	/**
	 * Function to determine the number of Feistel rounds for A10
	 */
	private final FFX.RoundCounter a10RoundCounter = new FFX.RoundCounter() {

		@Override
		public int rnds(int n) {
			if (n < 4 || n > 36)
				throw new IllegalArgumentException("n must be in the range [4..36]: " + n);
			else if (n <= 5)
				return 24;
			else if (n <= 9)
				return 18;
			else /* if (n <= 128) */
				return 12;
		}
	};

	/**
	 * Round function F for A10
	 */
	private final FFX.RoundFunction a10Round = new FFX.RoundFunction() {

		@Override
		public int[] F(SecretKey K, int n, byte[] T, int i, int[] B) throws InvalidKeyException {
			// algorithm F K(n, T, i, B)

			// vers <- 1; t <- |T|8
			int t = T.length;

			// P <- [vers]^2 || [method]^1 || [addition]^1 || [radix]^1 || [n]^1
			// || [split(n)]^1 || [rnds(n)]^1 || [t]^8
			byte[] obn = bytestring(n, 1);
			byte[] obs = bytestring(a10Splitter.split(n), 1);
			byte[] obr = bytestring(a10RoundCounter.rnds(n), 1);
			byte[] ebt = bytestring(t, 8);
			byte[] P = { 0, 1, 2, 1, (byte) getRadix(), obn[0], obs[0], obr[0], ebt[7], ebt[6], ebt[5], ebt[4], ebt[3],
					ebt[2], ebt[1], ebt[0] };

			// Q <- T || [0]^(-t-9 mod 16) || [i]^1 || [num10(B)]^8
			byte[] Q = T;
			Q = Common.concatenate(Q, bytestring(0, Common.mod(-t - 9, 16)));
			Q = Common.concatenate(Q, bytestring(i, 1));
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

			// Y' <- Y [1 .. 64]; Y'' <- Y [65 .. 128]
			byte[] Y1 = Arrays.copyOfRange(Y, 0, 8);
			byte[] Y2 = Arrays.copyOfRange(Y, 8, 16);

			// y' <- num2(Y'); y'' <- num2(Y'')
			BigInteger y1 = Common.num(Y1);
			BigInteger y2 = Common.num(Y2);

			// if even (i) then m <- split(n) else m <- n-split(n)
			int m = i % 2 == 0 ? a10Splitter.split(n) : n - a10Splitter.split(n);

			// if m <= 9 then z <- y'' mod 10^m
			// else z <- (y' mod 10^(m-9)) * 10^9 + (y'' mod 10^9)
			BigInteger z;
			if (m <= 9) {
				z = y2.mod(BigInteger.valueOf(10).pow(m));
			} else {
				// 10^9, for readability
				BigInteger oneBillion = BigInteger.valueOf(10).pow(9);

				z = y1.mod(BigInteger.valueOf(10).pow(m - 9)).multiply(oneBillion).add(y2.mod(oneBillion));
			}

			// return str m 10 (z)
			int[] Z = Common.str(z, getRadix(), m);
			return Z;
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
	 * Construct a new A10Parameters instance.
	 */
	public A10Parameters() {
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
		return 10;
	}

	@Override
	public int getMinLen() {
		return 4;
	}

	@Override
	public int getMaxLen() {
		return 36;
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
		return FFX.getBlockwiseArithmeticFunction(getRadix());
	}

	@Override
	public FeistelMethod getFeistelMethod() {
		return FeistelMethod.TWO;
	}

	@Override
	public SplitFunction getSplitter() {
		return a10Splitter;
	}

	@Override
	public RoundCounter getRoundCounter() {
		return a10RoundCounter;
	}

	@Override
	public RoundFunction getRoundFunction() {
		return a10Round;
	}
}
