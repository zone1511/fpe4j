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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Kai Johnson
 *
 */
class Functions {

	/**
	 * Comparator to sort integers in descending order
	 */
	static final Comparator<Integer> INTEGER_DESCENDING_COMPARATOR = new Comparator<Integer>() {
		@Override
		public int compare(Integer a, Integer b) {
			return b.compareTo(a);
		}
	};

	/**
	 * Vector of bytes containing the two’s compliment representation of an
	 * integer.
	 * <p>
	 * This is a direct implementation in place of the algorithm in the
	 * specification. It can be compared to bytesX(BigInteger) to verify it's
	 * correctness.
	 * <p>
	 * Inputs:<br>
	 * x, a constrained or unconstrained integer
	 * <p>
	 * Outputs:<br>
	 * X, a vector of bytes
	 * 
	 * @param x
	 *            two's compliment integer
	 * @return array of bytes representing x
	 */
	static byte[] bytes(BigInteger x) {
		// validate x
		if (x == null)
			throw new NullPointerException("x must not be null");

		return x.toByteArray();
	}

	/**
	 * Vector of bytes containing the two’s compliment representation of an
	 * integer.
	 * <p>
	 * This is a direct implementation in place of the algorithm in the
	 * specification. It can be compared to bytesX(int) to verify it's
	 * correctness.
	 * <p>
	 * Inputs:<br>
	 * x, a constrained or unconstrained integer
	 * <p>
	 * Outputs:<br>
	 * X, a vector of bytes
	 * 
	 * @param x
	 *            two's compliment integer
	 * @return array of bytes representing x
	 */
	static byte[] bytes(int x) {
		if (x >= Byte.MIN_VALUE && x <= Byte.MAX_VALUE)
			return new byte[] { (byte) x };
		else if (x >= Short.MIN_VALUE && x <= Short.MAX_VALUE)
			return new byte[] { (byte) (x >>> 8), (byte) x };
		else if (x >= 0xFF800000 && x <= 0x007FFFFF)
			return new byte[] { (byte) (x >>> 16), (byte) (x >>> 8), (byte) x };
		else
			return new byte[] { (byte) (x >>> 24), (byte) (x >>> 16), (byte) (x >>> 8), (byte) x };
	}

	/**
	 * Vector of bytes containing the two’s compliment representation of an
	 * integer.
	 * <p>
	 * Inputs:<br>
	 * x, a constrained or unconstrained integer
	 * <p>
	 * Outputs:<br>
	 * X, a vector of bytes
	 * 
	 * @param x
	 *            two's compliment integer
	 * @return array of bytes representing x
	 */
	static byte[] bytesX(BigInteger x) {
		// X<-{ }
		LinkedList<Byte> X = new LinkedList<Byte>();

		// Do
		do {
			// X<-{x mod 256} || X
			X.push(new Byte((byte) x.mod(BigInteger.valueOf(256)).intValue()));

			// x<-x div 256
			x = x.divide(BigInteger.valueOf(256));
		}
		// While x!=0
		while (x.signum() != 0);

		// convert the linked list into an array of bytes
		byte[] B = new byte[X.size()];
		int i = 0;
		for (Byte b : X) {
			B[i++] = b.byteValue();
		}

		return B;
	}

	/**
	 * Vector of bytes containing the two’s compliment representation of an
	 * integer.
	 * <p>
	 * Inputs:<br>
	 * x, a constrained or unconstrained integer
	 * <p>
	 * Outputs:<br>
	 * X, a vector of bytes
	 * 
	 * @param x
	 *            two's compliment integer
	 * @return array of bytes representing x
	 */
	static byte[] bytesX(int x) {
		// X<-{ }
		LinkedList<Byte> X = new LinkedList<Byte>();
		// Do
		do {
			// X<-{x mod 256} || X
			X.push(new Byte((byte) (x % 256)));

			// x<-x div 256
			x /= 256;
		}
		// While x!=0
		while (x != 0);

		// convert the linked list into an array of bytes
		byte[] B = new byte[X.size()];
		int i = 0;
		for (Byte b : X) {
			B[i++] = b.byteValue();
		}

		return B;
	}

	/**
	 * Prime factors of the integers in a vector. See Appendix A for alternative
	 * implementations.
	 * <p>
	 * Inputs:<br>
	 * W, a vector of integers of arbitrary length, where each integer is
	 * greater than or equal to two
	 * <p>
	 * Outputs:<br>
	 * G, a vector of integers of arbitrary length
	 * 
	 * @param W
	 *            a vector of integers of arbitrary length, where each integer
	 *            is greater than or equal to two
	 * @return a vector of integers of arbitrary length
	 */
	static List<Integer> factors(int[] W) {
		// validate W
		if (W == null)
			throw new NullPointerException("W must not be null");
		if (W.length < 1)
			throw new IllegalArgumentException("W must not be empty");

		// E<-primes(max(W))
		List<Integer>[] E = primes(max(W));

		// G = { }
		ArrayList<Integer> G = new ArrayList<Integer>(W.length);

		// For each w in W
		for (int w : W) {
			// validate w
			if (w < 2)
				throw new IllegalArgumentException("W must not contain integers less than 2: " + w);

			// G<-G || E(w)
			G.addAll(E[w]);
		}
		return G;
	}

	/**
	 * Two’s compliment integer represented by a byte vector.
	 * <p>
	 * This is a direct implementation in place of the algorithm in the
	 * specification. It can be compared to integerX(byte[]) to verify it's
	 * correctness.
	 * <p>
	 * Inputs:<br>
	 * X, a vector of bytes
	 * <p>
	 * Outputs:<br>
	 * x, an unconstrainted integer
	 * 
	 * @param X
	 *            array of bytes
	 * @return two's compliment integer represented by the array of bytes
	 */
	static BigInteger integer(byte[] X) {
		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < 1)
			throw new IllegalArgumentException("X must not be empty");

		return new BigInteger(X);

	}

	/**
	 * Two’s compliment integer represented by a byte vector.
	 * <p>
	 * Inputs:<br>
	 * X, a vector of bytes
	 * <p>
	 * Outputs:<br>
	 * x, an unconstrainted integer
	 * 
	 * @param X
	 *            array of bytes
	 * @return two's compliment integer represented by the array of bytes
	 */
	static BigInteger integerX(byte[] X) {
		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < 1)
			throw new IllegalArgumentException("X must not be empty");

		// y<-0
		BigInteger y = BigInteger.ZERO;

		// For each i in 0..length(X)-1
		for (int i = 0; i < X.length; i++) {
			// If i=0, y<-y × 256 + X[i]; else y<-y × 256 + X[i] mod 256
			if (i == 0) {
				y = y.multiply(BigInteger.valueOf(256)).add(BigInteger.valueOf(X[i]));
			} else {
				y = y.multiply(BigInteger.valueOf(256)).add(BigInteger.valueOf(X[i]).mod(BigInteger.valueOf(256)));
			}
		}

		return y;

	}

	/**
	 * Largest integer in the vector of integers W.
	 * 
	 * Inputs:<br>
	 * W, a vector of integers
	 * <p>
	 * Outputs:<br>
	 * x, the largest integer in W
	 * 
	 * @param W
	 *            an array of integers
	 * @return the largest integer in W
	 */
	static int max(int[] W) {
		// validate W
		if (W == null)
			throw new NullPointerException("W must not be null");
		if (W.length < 1)
			throw new IllegalArgumentException("W must not be empty");

		int x = Integer.MIN_VALUE;

		for (int w : W)
			if (w > x) {
				x = w;
			}

		return x;
	}

	/**
	 * Given a real number x and a positive integer m, returns the remainder of
	 * x modulo m, denoted by x mod m, which is x - m * floor(x/m).
	 * 
	 * @param x
	 *            The "real" number (defined as an int to avoid unnecessary type
	 *            conversion).
	 * @param m
	 *            The modulus.
	 * @return The nonnegative remainder of the integer x modulo the positive
	 *         integer m.
	 * @throws ArithmeticException
	 *             If m is less than 1.
	 */
	static int mod(int x, int m) {
		// validate m
		if (m < 1)
			throw new ArithmeticException("m must be a positive integer");

		// x - m * floor(x / m);
		return x - m * (int) Math.floor(x / (double) m);
	}

	/**
	 * Vector of x bytes containing zeros.
	 * <p>
	 * Inputs:<br>
	 * x, a constrained integer
	 * <p>
	 * Outputs:<br>
	 * X, a vector of bytes
	 * 
	 * @param x
	 *            the number of bytes
	 * @return array of x bytes containing zeros
	 */
	static byte[] padding(int x) {
		// validate x
		if (x < 0)
			throw new IllegalArgumentException("x must be nonnegative: " + x);

		// X<-{ 0,0,0,…,0 }, where the number of elements is determined by x.
		return new byte[x];
	}

	/**
	 * Generate a vector of x elements where the nth element contains a vector
	 * of the prime factors of n.
	 * <p>
	 * Input:<br>
	 * x, a constrained integer greater than 1
	 * <p>
	 * Output:<br>
	 * E, a vector of x elements where the nth element contains a vector of the
	 * prime factors of n
	 * 
	 * @param x
	 *            the upper limit of the search for primes
	 * @return an array of List&lt;Integer&gt; where each List contains the
	 *         prime factors of the index of the List; elements 0 and 1 are null
	 */
	@SuppressWarnings("unchecked")
	static List<Integer>[] primes(int x) {
		// validate x
		if (x < 2)
			throw new IllegalArgumentException("x must be greater than or equal to two: " + x);
		if (x > 65535)
			throw new IllegalArgumentException("x must be less than 65536: " + x);

		/*
		 * Although this modified sieve of Eratosthenes works with values of x
		 * greater than 65535, both space and time requirements quickly become
		 * impractical with larger values.
		 * 
		 * Expect the result to use about 5MB of memory for integer values plus
		 * Java object overhead if x = 65535.
		 * 
		 * However, if x is small, this algorithm is efficient in both space and
		 * time.
		 */

		// E<-{ { }_0,{ }_1,{ }_2,…,{ }_x}
		ArrayList<Integer>[] E = (ArrayList<Integer>[]) new ArrayList<?>[x + 1];

		// r<-ceiling(sqrt(x))
		int r = (int) Math.ceil(Math.sqrt(x));

		// For i in 2..r
		for (int i = 2; i <= r; i++) {
			// If E[i]!={ }, next i
			if (E[i] != null) {
				continue;
			}

			// j<-i
			int j = i;

			// While j × i<=x
			while (j * i <= x) {
				// E[j × i]<-E[j × i] || {i}
				if (E[j * i] == null) {
					E[j * i] = new ArrayList<Integer>();
				}
				E[j * i].add(new Integer(i));

				// j<-j+1
				j++;
			}
		}

		// For i in 2..x
		for (int i = 2; i <= x; i++) {
			// If E[i]={ }
			if (E[i] == null) {
				// E[i]={i}
				E[i] = new ArrayList<Integer>();
				E[i].add(Integer.valueOf(i));
			} else {
				// j<-i/product(E[i])
				int j = i / product(E[i]);

				// If j>1, E[i]<-E[i] || E[j]
				if (j > 1) {
					E[i].addAll(E[j]);
				}
			}
		}
		return E;
	}

	/**
	 * Product of the integers in a vector.
	 * <p>
	 * Modified form of the function for use within the search for prime
	 * factors. The restriction to integer range is appropriate because we never
	 * factor numbers outside this range.
	 * <p>
	 * Inputs:<br>
	 * X, a vector of positive integers of arbitrary length
	 * <p>
	 * Outputs:<br>
	 * y, an unconstrained integer
	 * 
	 * @param X
	 *            a vector of positive integers of arbitrary length
	 * @return an integer
	 */
	static int product(ArrayList<Integer> X) {
		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.size() < 1)
			throw new IllegalArgumentException("X must not be empty");

		// y<-1
		int y = 1;

		// For each element x of X
		for (Integer x : X) {
			// validate x
			if (x.intValue() < 1)
				throw new IllegalArgumentException("Elements of X must be positive integers: " + x);

			// validate x
			y = y * x.intValue();

			// check for overflow
			if (y < 1)
				throw new ArithmeticException("Product of X exceeds the range of int.");
		}

		return y;
	}

	/**
	 * Product of the integers in a vector.
	 * <p>
	 * Inputs:<br>
	 * X, a vector of positive integers of arbitrary length
	 * <p>
	 * Outputs:<br>
	 * y, an unconstrained integer
	 * 
	 * @param X
	 *            a vector of positive integers of arbitrary length
	 * @return an unconstrained integer
	 */
	static BigInteger product(int[] X) {
		// validate X
		if (X == null)
			throw new NullPointerException("X must not be null");
		if (X.length < 1)
			throw new IllegalArgumentException("X must not be empty");

		// y<-1
		BigInteger y = BigInteger.ONE;

		// For each element x of X
		for (int x : X) {
			// validate x
			if (x < 1)
				throw new IllegalArgumentException("Elements of X must be positive integers: " + x);

			// y<-y × x
			y = y.multiply(BigInteger.valueOf(x));
		}

		return y;
	}

	/**
	 * Number of Feistel rounds required for inputs with radices u and v.
	 * <p>
	 * Inputs:<br>
	 * u and v, unconstrained integers
	 * <p>
	 * Output<br>
	 * r, a constrained integer
	 * 
	 * @param u
	 *            radix of the left portion of W
	 * @param v
	 *            radix of the right portion of W
	 * @return the number of Feistel rounds
	 */
	static int rounds(BigInteger u, BigInteger v) {
		// validate u
		if (u == null)
			throw new NullPointerException("u must not be null");
		if (u.compareTo(BigInteger.valueOf(2)) < 0)
			throw new IllegalArgumentException("u must be greater than one: " + u);

		// validate v
		if (v == null)
			throw new NullPointerException("v must not be null");
		if (v.compareTo(BigInteger.valueOf(2)) < 0)
			throw new IllegalArgumentException("v must be greater than one: " + v);

		// x<-bitlength(v)
		int x = u.subtract(BigInteger.ONE).bitLength();

		// y<-bitlength(u)
		int y = v.subtract(BigInteger.ONE).bitLength();

		// If x<=y, r<-4 × ceiling((x+y)/x); else r<-4 × ceiling((x+y)/y)
		int r = 4 * (int) Math.ceil(1.0 * (x + y) / (x <= y ? x : y));

		return r;
	}

	/**
	 * Square root of an unconstrained integer, calculated using the Babylonian
	 * method
	 * <p>
	 * Inputs:<br>
	 * x, an unconstrained integer
	 * <p>
	 * Outputs:<br>
	 * y, the largest integer less than or equal to the square root of x
	 * 
	 * @param x
	 *            an unconstrained integer
	 * @return the square root of x
	 */
	static BigInteger sqrt(BigInteger x) {
		// validate x
		if (x == null)
			throw new NullPointerException("x must not be null.");
		if (x.compareTo(BigInteger.ZERO) < 0)
			throw new IllegalArgumentException("x must be non-negative: " + x);

		// square roots of 0 and 1 are trivial and
		// y == 0 will cause a divide-by-zero exception
		if (x.equals(BigInteger.ZERO) || x.equals(BigInteger.ONE))
			return x;

		BigInteger two = BigInteger.valueOf(2L);
		BigInteger y;

		// starting with y = x / 2 avoids magnitude issues with x squared
		for (y = x.divide(two); y.compareTo(x.divide(y)) > 0; y = x.divide(y).add(y).divide(two)) {
			//
		}
		return y;
	}

	/**
	 * Non-instantiable class.
	 */
	Functions() {
		throw new RuntimeException("The Functions class cannot be instantiated.");
	}
}
