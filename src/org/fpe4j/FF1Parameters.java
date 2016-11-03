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

import org.fpe4j.FFX.ArithmeticFunction;
import org.fpe4j.FFX.FFXParameters;
import org.fpe4j.FFX.FeistelMethod;
import org.fpe4j.FFX.RoundCounter;
import org.fpe4j.FFX.RoundFunction;
import org.fpe4j.FFX.SplitFunction;

/**
 * FFX parameter set for the FF1 algorithm defined in NIST SP 800-38G.
 * 
 * @author Kai Johnson
 *
 */
public class FF1Parameters implements FFXParameters {

	/**
	 * The radix specified in this parameter set.
	 */
	private final int radix;

	/**
	 * Instances of AES ciphers for PRF and CIPH algorithms.
	 */
	private final Ciphers ciphers;

	/**
	 * Split function for FF1.
	 */
	private final FFX.SplitFunction ff1Splitter = new FFX.SplitFunction() {

		@Override
		public int split(int n) {
			// validate n
			if (n < Constants.MINLEN || n > Constants.MAXLEN)
				throw new IllegalArgumentException(
						"n must be in the range [" + Constants.MINLEN + ".." + Constants.MAXLEN + "].");
			return floor(n / 2.0);
		}
	};

	/**
	 * Function to determine the number of Feistel rounds for FF1.
	 */
	private final FFX.RoundCounter ff1RoundCounter = new FFX.RoundCounter() {

		@Override
		public int rnds(int n) {
			return 10;
		}
	};

	/**
	 * Round function F for FF1, derived from NIST SP 800-38G.
	 */
	private final FFX.RoundFunction ff1Round = new FFX.RoundFunction() {

		@Override
		public boolean validKey(SecretKey K) {
			// validate K
			if (K == null)
				return false;
			if (!K.getAlgorithm().equals("AES"))
				return false;
			return true;
		}

		@Override
		public int[] F(SecretKey K, int n, byte[] T, int i, int[] B) throws InvalidKeyException {

			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Round #" + i + "\n");
			}

			// value of t for readability
			int t = T.length;

			// 1. Let u = floor(n/2); v = n – u.
			int u = floor(n / 2.0);
			int v = n - u;
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 1\n\tu is " + u + ", v is " + v);
			}

			// 2. Let A = X[1..u]; B = X[u + 1..n].
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 2\n\tB is " + intArrayToString(B));
			}

			// 3. Let b = ceiling(ceiling(v * LOG(radix))/8).
			int b = ceiling(ceiling(v * log2(radix)) / 8.0);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 3\n\tb is " + b);
			}

			// 4. Let d = 4 * ceiling(b/4) + 4.
			int d = 4 * ceiling(b / 4.0) + 4;
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 4\n\td is " + d);
			}

			// 5. Let P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 ||
			// [u mod 256]^1 || [n]^4 || [t]^4 .
			byte[] tbr = bytestring(radix, 3);
			byte[] fbn = bytestring(n, 4);
			byte[] fbt = bytestring(t, 4);
			byte[] P = { (byte) 0x01, (byte) 0x02, (byte) 0x01, tbr[0], tbr[1], tbr[2], (byte) 0x0A,
					(byte) (mod(u, 256) & 0xFF), fbn[0], fbn[1], fbn[2], fbn[3], fbt[0], fbt[1], fbt[2], fbt[3] };
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 5\n\tP is " + unsignedByteArrayToString(P));
			}

			// i. Let Q = T || [0]^(-t-b-1) mod 16 || [i]^1 || [NUMradix
			// (B)]^b
			byte[] Q = concatenate(T, bytestring(0, mod(-t - b - 1, 16)));
			Q = concatenate(Q, bytestring(i, 1));
			Q = concatenate(Q, bytestring(num(B, radix), b));
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 6.i.\n\tQ is " + unsignedByteArrayToString(Q));
			}

			// ii. Let R = PRF(P || Q).
			byte[] R = ciphers.prf(K, concatenate(P, Q));
			// byte[] R = concatenate(prf(K, concatenate(P, Q)), P);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 6.ii.\n\tR is " + unsignedByteArrayToString(R));
			}

			// iii. Let S be the first d bytes of the following string of
			// ceiling(d/16) blocks: R || CIPH K (R xor [1]^16 ) || CIPH K
			// (R xor [2]^16 ) … CIPH K (R xor [ceiling(d/16)–1]^16 ).
			byte[] S = R;
			for (int j = 1; j <= ceiling(d / 16.0) - 1; j++) {
				S = concatenate(S, ciphers.ciph(K, xor(R, bytestring(j, 16))));
			}
			S = Arrays.copyOf(S, d);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 6.iii.\n\tS is " + byteArrayToHexString(S));
			}

			// iv. Let y = NUM(S).
			BigInteger y = num(S);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 6.iv.\n\ty is " + y);
			}

			// v. If i is even, let m = u; else, let m = v.
			int m = i % 2 == 0 ? u : v;
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 6.v.\n\tm is " + m);
			}

			// constrain y to the range [0..radix^m]
			y = Common.mod(y, BigInteger.valueOf(radix).pow(m));

			// Step 7. Let Y = STR m radix (y).
			int[] Y = str(y, radix, m);
			if (Constants.CONFORMANCE_OUTPUT) {
				System.out.println("Step 7.\n\tY is " + intArrayToString(Y) + "\n");
			}

			return Y;
		}
	};

	/**
	 * Construct a new FF1Parameters instance with the specified radix.
	 * 
	 * @param radix
	 *            the radix for FF1 operations
	 */
	public FF1Parameters(int radix) {
		this.radix = radix;
		ciphers = new Ciphers();
	}

	@Override
	public int getRadix() {
		return radix;
	}

	@Override
	public int getMinLen() {
		return Constants.MINLEN;
	}

	@Override
	public int getMaxLen() {
		return Constants.MAXLEN;
	}

	@Override
	public int getMinTLen() {
		return 0;
	}

	@Override
	public int getMaxTLen() {
		return Constants.MAXLEN;
	}

	@Override
	public ArithmeticFunction getArithmeticFunction() {
		return FFX.getBlockwiseArithmeticFunction(radix);
	}

	@Override
	public FeistelMethod getFeistelMethod() {
		return FeistelMethod.TWO;
	}

	@Override
	public SplitFunction getSplitter() {
		return ff1Splitter;
	}

	@Override
	public RoundCounter getRoundCounter() {
		return ff1RoundCounter;
	}

	@Override
	public RoundFunction getRoundFunction() {
		return ff1Round;
	}
}
