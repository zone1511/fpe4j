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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.fpe4j.utilities.Utilities;
import org.junit.Test;

/**
 * JUnit test cases for the Functions class
 * 
 * @author Kai Johnson
 *
 */
public class FunctionsTest {

	/**
	 * Test method for
	 * {@link org.fpe4j.ifx.Functions#bytes(java.math.BigInteger)}.
	 */
	@Test
	public void testBytesBigInteger() {
		// null
		try {
			Functions.bytes(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		// zero
		byte[] b1 = { (byte) 0x00 };
		assertArrayEquals(b1, Functions.bytes(BigInteger.ZERO));
		assertArrayEquals(b1, Functions.bytesX(BigInteger.ZERO));

		// one
		byte[] b2 = { (byte) 0x01 };
		assertArrayEquals(b2, Functions.bytes(BigInteger.ONE));
		assertArrayEquals(b2, Functions.bytesX(BigInteger.ONE));

		// minus one
		byte[] b3 = { (byte) 0xFF };
		assertArrayEquals(b3, Functions.bytes(BigInteger.ONE.negate()));
		assertArrayEquals(b3, Functions.bytesX(BigInteger.ONE.negate()));

		// Byte.MIN_VALUE
		byte[] b4 = { (byte) 0x80 };
		assertArrayEquals(b4, Functions.bytes(BigInteger.valueOf(Byte.MIN_VALUE)));
		assertArrayEquals(b4, Functions.bytesX(BigInteger.valueOf(Byte.MIN_VALUE)));

		// Byte.MAX_VALUE
		byte[] b5 = { (byte) 0x7F };
		assertArrayEquals(b5, Functions.bytes(BigInteger.valueOf(Byte.MAX_VALUE)));
		assertArrayEquals(b5, Functions.bytesX(BigInteger.valueOf(Byte.MAX_VALUE)));

		// Short.MIN_VALUE
		byte[] b6 = { (byte) 0x80, (byte) 0x00 };
		assertArrayEquals(b6, Functions.bytes(BigInteger.valueOf(Short.MIN_VALUE)));
		assertArrayEquals(b6, Functions.bytesX(BigInteger.valueOf(Short.MIN_VALUE)));

		// Short.MAX_VALUE
		byte[] b7 = { (byte) 0x7F, (byte) 0xFF };
		assertArrayEquals(b7, Functions.bytes(BigInteger.valueOf(Short.MAX_VALUE)));
		assertArrayEquals(b7, Functions.bytesX(BigInteger.valueOf(Short.MAX_VALUE)));

		// Three-byte minimum
		byte[] b8 = { (byte) 0x80, (byte) 0x00, (byte) 0x00 };
		assertArrayEquals(b8, Functions.bytes(BigInteger.valueOf(-8388608)));
		assertArrayEquals(b8, Functions.bytesX(BigInteger.valueOf(-8388608)));

		// Three-byte maximum
		byte[] b9 = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(b9, Functions.bytes(BigInteger.valueOf(8388607)));
		assertArrayEquals(b9, Functions.bytesX(BigInteger.valueOf(8388607)));

		// Integer.MIN_VALUE
		byte[] b10 = { (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		assertArrayEquals(b10, Functions.bytes(BigInteger.valueOf(Integer.MIN_VALUE)));
		assertArrayEquals(b10, Functions.bytesX(BigInteger.valueOf(Integer.MIN_VALUE)));

		// Integer.MAX_VALUE
		byte[] b11 = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(b11, Functions.bytes(BigInteger.valueOf(Integer.MAX_VALUE)));
		assertArrayEquals(b11, Functions.bytesX(BigInteger.valueOf(Integer.MAX_VALUE)));

		// Sixteen-byte minimum
		byte[] b12 = Utilities.hexStringToByteArray("80000000000000000000000000000000");
		assertArrayEquals(b12, Functions.bytes(new BigInteger("-170141183460469231731687303715884105728")));
		assertArrayEquals(b12, Functions.bytesX(new BigInteger("-170141183460469231731687303715884105728")));

		// Sixteen-byte maximum
		byte[] b13 = Utilities.hexStringToByteArray("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
		assertArrayEquals(b13, Functions.bytes(new BigInteger("170141183460469231731687303715884105727")));
		assertArrayEquals(b13, Functions.bytesX(new BigInteger("170141183460469231731687303715884105727")));
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#bytes(int)}.
	 */
	@Test
	public void testBytesInt() {
		// zero
		byte[] b1 = { (byte) 0x00 };
		assertArrayEquals(b1, Functions.bytes(0));
		assertArrayEquals(b1, Functions.bytesX(0));

		// one
		byte[] b2 = { (byte) 0x01 };
		assertArrayEquals(b2, Functions.bytes(1));
		assertArrayEquals(b2, Functions.bytesX(1));

		// minus one
		byte[] b3 = { (byte) 0xFF };
		assertArrayEquals(b3, Functions.bytes(-1));
		assertArrayEquals(b3, Functions.bytesX(-1));

		// Byte.MIN_VALUE
		byte[] b4 = { (byte) 0x80 };
		assertArrayEquals(b4, Functions.bytes(Byte.MIN_VALUE));
		assertArrayEquals(b4, Functions.bytesX(Byte.MIN_VALUE));

		// Byte.MAX_VALUE
		byte[] b5 = { (byte) 0x7F };
		assertArrayEquals(b5, Functions.bytes(Byte.MAX_VALUE));
		assertArrayEquals(b5, Functions.bytesX(Byte.MAX_VALUE));

		// Short.MIN_VALUE
		byte[] b6 = { (byte) 0x80, (byte) 0x00 };
		assertArrayEquals(b6, Functions.bytes(Short.MIN_VALUE));
		assertArrayEquals(b6, Functions.bytesX(Short.MIN_VALUE));

		// Short.MAX_VALUE
		byte[] b7 = { (byte) 0x7F, (byte) 0xFF };
		assertArrayEquals(b7, Functions.bytes(Short.MAX_VALUE));
		assertArrayEquals(b7, Functions.bytesX(Short.MAX_VALUE));

		// Three-byte minimum
		byte[] b8 = { (byte) 0x80, (byte) 0x00, (byte) 0x00 };
		assertArrayEquals(b8, Functions.bytes(-8388608));
		assertArrayEquals(b8, Functions.bytesX(-8388608));

		// Three-byte maximum
		byte[] b9 = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(b9, Functions.bytes(8388607));
		assertArrayEquals(b9, Functions.bytesX(8388607));

		// Integer.MIN_VALUE
		byte[] b10 = { (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		assertArrayEquals(b10, Functions.bytes(Integer.MIN_VALUE));
		assertArrayEquals(b10, Functions.bytesX(Integer.MIN_VALUE));

		// Integer.MAX_VALUE
		byte[] b11 = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(b11, Functions.bytes(Integer.MAX_VALUE));
		assertArrayEquals(b11, Functions.bytesX(Integer.MAX_VALUE));
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#factors(int[])}.
	 */
	@Test
	public void testFactors() {
		// null
		try {
			Functions.factors(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			Functions.factors(new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// negative
		try {
			int[] W = { 2, 4, -2, -4 };
			Functions.factors(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// less than two
		try {
			int[] W = { 3, 2, 1, 0 };
			Functions.factors(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// greater than 65535
		try {
			int[] W = { 65536 };
			Functions.factors(W);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one element
		int[] W1 = { 65534 };
		List<Integer> G1 = Functions.factors(W1);
		int[] expected1 = { 2, 7, 31, 151 };
		assertEquals(expected1.length, G1.size());
		for (int i = 0; i < expected1.length; i++) {
			assertEquals(expected1[i], G1.get(i).intValue());
		}

		// many elements
		int[] W2 = { 10, 26, 26, 26, 10, 10, 10 };
		List<Integer> G2 = Functions.factors(W2);
		int[] expected2 = { 2, 5, 2, 13, 2, 13, 2, 13, 2, 5, 2, 5, 2, 5 };
		assertEquals(expected2.length, G2.size());
		for (int i = 0; i < expected2.length; i++) {
			assertEquals(expected2[i], G2.get(i).intValue());
		}

		// fuzz
		Random random = new Random();
		for (int i = 0; i < 100; i++) {
			int[] W = new int[10];
			for (int j = 0; j < 10; j++) {
				W[j] = random.nextInt(65534) + 2;
			}
			BigInteger w = Functions.product(W);
			List<Integer> G = Functions.factors(W);
			BigInteger x = BigInteger.ONE;
			for (Integer g : G) {
				x = x.multiply(BigInteger.valueOf(g.intValue()));
			}
			assertTrue(w.compareTo(x) == 0);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#Functions()}.
	 */
	@Test
	public void testFunctions() {
		try {
			new Functions();
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof RuntimeException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#integer(byte[])}.
	 */
	@Test
	public void testInteger() {
		// null
		try {
			Functions.integer(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			Functions.integerX(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			Functions.integer(new byte[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			Functions.integerX(new byte[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		byte[] X1 = Utilities.hexStringToByteArray("00");
		BigInteger x1 = new BigInteger("0");
		assertTrue(x1.compareTo(Functions.integer(X1)) == 0);
		assertTrue(x1.compareTo(Functions.integerX(X1)) == 0);

		// one
		byte[] X2 = Utilities.hexStringToByteArray("01");
		BigInteger x2 = new BigInteger("1");
		assertTrue(x2.compareTo(Functions.integer(X2)) == 0);
		assertTrue(x2.compareTo(Functions.integerX(X2)) == 0);

		// minus one
		byte[] X3 = Utilities.hexStringToByteArray("FF");
		BigInteger x3 = new BigInteger("-1");
		assertTrue(x3.compareTo(Functions.integer(X3)) == 0);
		assertTrue(x3.compareTo(Functions.integerX(X3)) == 0);

		// Byte.MIN_VALUE
		byte[] X4 = Utilities.hexStringToByteArray("80");
		BigInteger x4 = new BigInteger("-128");
		assertTrue(x4.compareTo(Functions.integer(X4)) == 0);
		assertTrue(x4.compareTo(Functions.integerX(X4)) == 0);

		// Byte.MAX_VALUE
		byte[] X5 = Utilities.hexStringToByteArray("7F");
		BigInteger x5 = new BigInteger("127");
		assertTrue(x5.compareTo(Functions.integer(X5)) == 0);
		assertTrue(x5.compareTo(Functions.integerX(X5)) == 0);

		// Short.MIN_VALUE
		byte[] X6 = Utilities.hexStringToByteArray("8000");
		BigInteger x6 = new BigInteger("-32768");
		assertTrue(x6.compareTo(Functions.integer(X6)) == 0);
		assertTrue(x6.compareTo(Functions.integerX(X6)) == 0);

		// Short.MAX_VALUE
		byte[] X7 = Utilities.hexStringToByteArray("7FFF");
		BigInteger x7 = new BigInteger("32767");
		assertTrue(x7.compareTo(Functions.integer(X7)) == 0);
		assertTrue(x7.compareTo(Functions.integerX(X7)) == 0);

		// Three-byte minimum
		byte[] X8 = Utilities.hexStringToByteArray("800000");
		BigInteger x8 = new BigInteger("-8388608");
		assertTrue(x8.compareTo(Functions.integer(X8)) == 0);
		assertTrue(x8.compareTo(Functions.integerX(X8)) == 0);

		// Three-byte maximum
		byte[] X9 = Utilities.hexStringToByteArray("7FFFFF");
		BigInteger x9 = new BigInteger("8388607");
		assertTrue(x9.compareTo(Functions.integer(X9)) == 0);
		assertTrue(x9.compareTo(Functions.integerX(X9)) == 0);

		// Integer.MIN_VALUE
		byte[] X10 = Utilities.hexStringToByteArray("80000000");
		BigInteger x10 = new BigInteger("-2147483648");
		assertTrue(x10.compareTo(Functions.integer(X10)) == 0);
		assertTrue(x10.compareTo(Functions.integerX(X10)) == 0);

		// Integer.MAX_VALUE
		byte[] X11 = Utilities.hexStringToByteArray("7FFFFFFF");
		BigInteger x11 = new BigInteger("2147483647");
		assertTrue(x11.compareTo(Functions.integer(X11)) == 0);
		assertTrue(x11.compareTo(Functions.integerX(X11)) == 0);

		// Sixteen-byte minimum
		byte[] X12 = Utilities.hexStringToByteArray("80000000000000000000000000000000");
		BigInteger x12 = new BigInteger("-170141183460469231731687303715884105728");
		assertTrue(x12.compareTo(Functions.integer(X12)) == 0);
		assertTrue(x12.compareTo(Functions.integerX(X12)) == 0);

		// Sixteen-byte maximum
		byte[] X13 = Utilities.hexStringToByteArray("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
		BigInteger x13 = new BigInteger("170141183460469231731687303715884105727");
		assertTrue(x13.compareTo(Functions.integer(X13)) == 0);
		assertTrue(x13.compareTo(Functions.integerX(X13)) == 0);

	}

	/**
	 * Test method for
	 * {@link org.fpe4j.ifx.Functions#INTEGER_DESCENDING_COMPARATOR}.
	 * 
	 */
	@Test
	public void TestIntegerDescendingComparator() {
		Integer[] X = { Integer.valueOf(0), Integer.valueOf(6), Integer.valueOf(7), Integer.valueOf(5),
				Integer.valueOf(8), Integer.valueOf(4), Integer.valueOf(9), Integer.valueOf(2), Integer.valueOf(3),
				Integer.valueOf(1) };
		Integer[] Y = { Integer.valueOf(9), Integer.valueOf(8), Integer.valueOf(7), Integer.valueOf(6),
				Integer.valueOf(5), Integer.valueOf(4), Integer.valueOf(3), Integer.valueOf(2), Integer.valueOf(1),
				Integer.valueOf(0) };
		ArrayList<Integer> G = new ArrayList<Integer>();
		ArrayList<Integer> H = new ArrayList<Integer>();

		// null
		try {
			Collections.sort(null, Functions.INTEGER_DESCENDING_COMPARATOR);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		Collections.sort(G, Functions.INTEGER_DESCENDING_COMPARATOR);
		assertEquals(0, G.size());

		for (Integer x : X) {
			G.add(x);
		}
		for (Integer y : Y) {
			H.add(y);
		}

		// unsorted
		Collections.sort(G, Functions.INTEGER_DESCENDING_COMPARATOR);
		for (int i = 0; i < G.size(); i++) {
			assertEquals(H.get(i), G.get(i));
		}

		// sorted
		Collections.sort(G, Functions.INTEGER_DESCENDING_COMPARATOR);
		for (int i = 0; i < G.size(); i++) {
			assertEquals(H.get(i), G.get(i));
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#max(int[])}.
	 */
	@Test
	public void testMax() {
		// null
		try {
			Functions.max(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			Functions.max(new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one element
		int[] W1 = { 65535 };
		assertEquals(W1[0], Functions.max(W1));

		// many elements
		int[] W2 = { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 5, 5, 5, 7, 7, 11, 13, 13, 17, 17, 19, 29,
				47, 61, 89, 233, 1597 };
		assertEquals(W2[34], Functions.max(W2));

	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#mod(int, int)}.
	 */
	@Test
	public void testModIntInt() {
		// examples from NIST SP 800-38G
		assertEquals(4, Functions.mod(-3, 7));
		assertEquals(6, Functions.mod(13, 7));

		// equivalence to Math.floorMod()
		assertEquals(4, Math.floorMod(-3, 7));
		assertEquals(6, Math.floorMod(13, 7));

		// negative modulus
		try {
			Functions.mod(13, -7);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}
		assertEquals(-1, Math.floorMod(13, -7));
		/*
		 * Note that Math.floorMod() permits negative moduli where NIST SP
		 * 800-38G does not.
		 */

		// zero modulus
		try {
			Functions.mod(13, 0);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}
		try {
			Math.floorMod(13, 0);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#padding(int)}.
	 */
	@Test
	public void testPadding() {
		// negative
		try {
			Functions.padding(-1);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		byte[] b1 = {};
		assertArrayEquals(b1, Functions.padding(0));

		// positive
		byte[] b2 = { 0, 0, 0, 0, 0 };
		assertArrayEquals(b2, Functions.padding(5));
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#primes(int)}.
	 */
	@Test
	public void testPrimes() {
		// negative
		try {
			Functions.primes(-1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		try {
			Functions.primes(0);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one
		try {
			Functions.primes(1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// too large
		try {
			Functions.primes(65536);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// positive
		List<Integer>[] E1 = Functions.primes(2);
		assertEquals(3, E1.length);
		assertNull(E1[0]);
		assertNull(E1[1]);
		assertEquals(1, E1[2].size());
		assertEquals(2, E1[2].get(0).intValue());

		// exhaustive
		List<Integer>[] E2 = Functions.primes(65535);
		assertEquals(65536, E2.length);
		assertNull(E2[0]);
		assertNull(E2[1]);
		for (int i = 2; i <= 65535; i++) {
			int j = 1;
			for (Integer e : E2[i]) {
				assertEquals(1, E2[e.intValue()].size());
				j *= e.intValue();
			}
			assertEquals(i, j);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#product(ArrayList)}.
	 */
	@Test
	public void testProductArrayListInteger() {
		// null
		try {
			Functions.product((ArrayList<Integer>) null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			Functions.product(new ArrayList<Integer>());
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// negative
		try {
			ArrayList<Integer> X = new ArrayList<Integer>();
			X.add(new Integer(1));
			X.add(new Integer(2));
			X.add(new Integer(-1));
			X.add(new Integer(-2));
			Functions.product(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		try {
			ArrayList<Integer> X = new ArrayList<Integer>();
			X.add(new Integer(3));
			X.add(new Integer(2));
			X.add(new Integer(1));
			X.add(new Integer(0));
			Functions.product(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one element
		ArrayList<Integer> X1 = new ArrayList<Integer>();
		X1.add(new Integer(256));
		int x1 = Functions.product(X1);
		assertEquals(x1, X1.get(0).intValue());

		// many elements
		ArrayList<Integer> X2 = new ArrayList<Integer>();
		X2.add(new Integer(3));
		X2.add(new Integer(5));
		X2.add(new Integer(17));
		X2.add(new Integer(257));
		int x2 = Functions.product(X2);
		assertEquals(65535, x2);

		// overflow
		try {
			ArrayList<Integer> X = new ArrayList<Integer>();
			X.add(new Integer(1));
			X.add(new Integer(1));
			X.add(new Integer(2));
			X.add(new Integer(3));
			X.add(new Integer(5));
			X.add(new Integer(8));
			X.add(new Integer(13));
			X.add(new Integer(21));
			X.add(new Integer(34));
			X.add(new Integer(55));
			X.add(new Integer(89));
			X.add(new Integer(144));
			X.add(new Integer(233));
			X.add(new Integer(377));
			X.add(new Integer(610));
			X.add(new Integer(987));
			X.add(new Integer(1597));
			X.add(new Integer(2584));
			Functions.product(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#product(int[])}.
	 */
	@Test
	public void testProductInt() {
		// null
		try {
			Functions.product((int[]) null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty
		try {
			Functions.product(new int[0]);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// negative
		try {
			int[] X = { 1, 2, -1, -2 };
			Functions.product(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		try {
			int[] X = { 3, 2, 1, 0 };
			Functions.product(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one element
		int[] X1 = { 256 };
		BigInteger x1 = Functions.product(X1);
		assertTrue(x1.compareTo(BigInteger.valueOf(X1[0])) == 0);

		// many elements
		int[] X2 = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584 };
		BigInteger x2 = Functions.product(X2);
		assertTrue(x2.compareTo(new BigInteger("342696507457909818131702784000")) == 0);
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.ifx.Functions#rounds(java.math.BigInteger, java.math.BigInteger)}.
	 */
	@Test
	public void testRounds() {
		// null
		try {
			Functions.rounds(null, BigInteger.TEN);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			Functions.rounds(BigInteger.TEN, null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// negative
		try {
			Functions.rounds(BigInteger.TEN.negate(), BigInteger.TEN);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			Functions.rounds(BigInteger.TEN, BigInteger.TEN.negate());
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		try {
			Functions.rounds(BigInteger.ZERO, BigInteger.TEN);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			Functions.rounds(BigInteger.TEN, BigInteger.ZERO);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one
		try {
			Functions.rounds(BigInteger.ONE, BigInteger.TEN);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			Functions.rounds(BigInteger.TEN, BigInteger.ONE);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// balanced
		int r1 = Functions.rounds(BigInteger.TEN, BigInteger.TEN);
		assertEquals(8, r1);
		int r2 = Functions.rounds(BigInteger.valueOf(2).pow(127), BigInteger.valueOf(2).pow(127));
		assertEquals(8, r2);

		// imbalanced
		int r3 = Functions.rounds(BigInteger.TEN, BigInteger.valueOf(100));
		assertEquals(12, r3);
		int r4 = Functions.rounds(BigInteger.valueOf(100), BigInteger.TEN);
		assertEquals(12, r4);

		// thorp
		int r5 = Functions.rounds(BigInteger.valueOf(2), BigInteger.valueOf(2).pow(127));
		assertEquals(512, r5);
		int r6 = Functions.rounds(BigInteger.valueOf(2).pow(127), BigInteger.valueOf(2));
		assertEquals(512, r6);
	}

	/**
	 * Test method for {@link org.fpe4j.ifx.Functions#sqrt(BigInteger)}.
	 */
	@Test
	public void testSqrt() {
		// null
		try {
			Functions.sqrt(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// negative
		try {
			Functions.sqrt(BigInteger.ONE.negate());
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		assertTrue(BigInteger.ZERO.compareTo(Functions.sqrt(BigInteger.ZERO)) == 0);

		// one
		assertTrue(BigInteger.ONE.compareTo(Functions.sqrt(BigInteger.ONE)) == 0);

		// sample values
		int[] numbers = { 0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584 };
		int[] expected = { 0, 1, 1, 1, 2, 2, 3, 4, 5, 7, 9, 12, 15, 19, 24, 31, 39, 50 };

		for (int i = 0; i < numbers.length; i++) {
			assertEquals(expected[i], Functions.sqrt(BigInteger.valueOf(numbers[i])).intValue());
		}
	}
}
