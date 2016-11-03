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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Test;

/**
 * JUnit test cases for the Common class.
 * 
 * @author Kai Johnson
 *
 */
public class CommonTest {

	/**
	 * Test method for {@link org.fpe4j.Common#Common()}.
	 */
	@Test
	public void testCommon() {
		try {
			new Common();
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof RuntimeException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.Common#num(int[], int)}.
	 */
	@Test
	public void testNumIntArrayInt() {
		// example from NIST SP 800-38G
		int[] X1 = { 0, 0, 0, 1, 1, 0, 1, 0 };
		assertTrue(Common.num(X1, 5).compareTo(BigInteger.valueOf(755)) == 0);

		// null input
		try {
			Common.num(null, 10);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// input array too short
		try {
			int[] X = {};
			Common.num(X, 10);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// input array too long
		try {
			int[] X = new int[Constants.MAXLEN + 1];
			Common.num(X, 10);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix too small
		try {
			int[] X = { 0, 1, 2, 3, 4, 5 };
			Common.num(X, 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix too large
		try {
			int[] X = { 0, 1, 2, 3, 4, 5 };
			Common.num(X, 65537);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// values outside the range of the radix
		try {
			int[] X = { 0, 1, 2, 3, 4, 5 };
			Common.num(X, 4);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// negative values
		try {
			int[] X = { 0, 1, -2, 3, 4, 5 };
			Common.num(X, 4);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// byte value
		int[] X2 = { 1, 1, 1, 1, 1, 1, 1, 1 };
		assertTrue(Common.num(X2, 2).compareTo(BigInteger.valueOf(255)) == 0);

		// short value
		int[] X3 = { 15, 15, 15, 15 };
		assertTrue(Common.num(X3, 16).compareTo(BigInteger.valueOf(65535)) == 0);

		// int value
		int[] X4 = { 127, 255, 255, 255 };
		assertTrue(Common.num(X4, 256).compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) == 0);

		// long value
		int[] X5 = { 255, 255, 255, 255 };
		assertTrue(Common.num(X5, 256).compareTo(BigInteger.valueOf(4294967295L)) == 0);

		// yotta
		int[] X6 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		assertTrue(Common.num(X6, 256).compareTo(BigInteger.valueOf(2).pow(80)) == 0);
	}

	/**
	 * Test method for {@link org.fpe4j.Common#num(byte[])}.
	 */
	@Test
	public void testNumByteArray() {
		// null input
		try {
			byte[] X = null;
			Common.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// input array too short
		try {
			byte[] X = {};
			Common.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// input array too long
		try {
			byte[] X = new byte[Constants.MAXLEN + 1];
			Common.num(X);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one byte values
		byte[] X1 = { (byte) 0x00 };
		assertTrue(BigInteger.valueOf(0).equals(Common.num(X1)));
		byte[] X2 = { (byte) 0x01 };
		assertTrue(BigInteger.valueOf(1).equals(Common.num(X2)));
		byte[] X3 = { (byte) 0x80 };
		assertTrue(BigInteger.valueOf(128).equals(Common.num(X3)));
		byte[] X4 = { (byte) 0xFF };
		assertTrue(BigInteger.valueOf(255).equals(Common.num(X4)));

		// two byte values
		byte[] X5 = { (byte) 0x00, (byte) 0x00 };
		assertTrue(BigInteger.valueOf(0).equals(Common.num(X5)));
		byte[] X6 = { (byte) 0x00, (byte) 0x01 };
		assertTrue(BigInteger.valueOf(1).equals(Common.num(X6)));
		byte[] X7 = { (byte) 0x80, (byte) 0x00 };
		assertTrue(BigInteger.valueOf(32768).equals(Common.num(X7)));
		byte[] X8 = { (byte) 0xFF, (byte) 0xFF };
		assertTrue(BigInteger.valueOf(65535).equals(Common.num(X8)));

		// four byte values
		byte[] X9 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		assertTrue(BigInteger.valueOf(0).equals(Common.num(X9)));
		byte[] X10 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 };
		assertTrue(BigInteger.valueOf(1).equals(Common.num(X10)));
		byte[] X11 = { (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		assertTrue(BigInteger.valueOf(2147483648L).equals(Common.num(X11)));
		byte[] X12 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		assertTrue(BigInteger.valueOf(4294967295L).equals(Common.num(X12)));

		// yotta
		byte[] X13 = { (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		assertTrue(BigInteger.valueOf(2).pow(80).equals(Common.num(X13)));
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.Common#str(java.math.BigInteger, int, int)}.
	 */
	@Test
	public void testStr() {
		// example from NIST SP 800-38G
		int[] expected1 = { 0, 3, 10, 7 };
		assertArrayEquals(expected1, Common.str(BigInteger.valueOf(559), 12, 4));

		// m is too small
		try {
			Common.str(BigInteger.ONE, 10, 0);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// m is too small
		try {
			Common.str(BigInteger.ONE, 10, Constants.MAXLEN + 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix is too small
		try {
			Common.str(BigInteger.ONE, 1, 4);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// radix is too large
		try {
			Common.str(BigInteger.ONE, 65537, 4);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// null input
		try {
			Common.str(null, 10, 4);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// X is negative
		try {
			Common.str(BigInteger.ONE.negate(), 10, 4);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// X is too large
		try {
			int[] X = { 0, 0, 0, 0 };
			assertArrayEquals(X, Common.str(BigInteger.valueOf(10).pow(4), 10, 4));
			fail();

		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			// fail();
		}
		/*
		 * Note that this test case is modified to accommodate the FFX
		 * algorithms.
		 */

		// byte value
		int[] X2 = { 1, 1, 1, 1, 1, 1, 1, 1 };
		assertArrayEquals(X2, Common.str(BigInteger.valueOf(255), 2, 8));

		// short value
		int[] X3 = { 15, 15, 15, 15 };
		assertArrayEquals(X3, Common.str(BigInteger.valueOf(65535), 16, 4));

		// int value
		int[] X4 = { 127, 255, 255, 255 };
		assertArrayEquals(X4, Common.str(BigInteger.valueOf(Integer.MAX_VALUE), 256, 4));

		// long value
		int[] X5 = { 255, 255, 255, 255 };
		assertArrayEquals(X5, Common.str(BigInteger.valueOf(4294967295L), 256, 4));

		// yotta
		int[] X6 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		assertArrayEquals(X6, Common.str(BigInteger.valueOf(2).pow(80), 256, 11));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#rev(int[])}.
	 */
	@Test
	public void testRev() {
		// example from NIST SP 800-38G
		int[] X1 = { 1, 3, 5, 7, 9 };
		int[] Y1 = { 9, 7, 5, 3, 1 };
		assertArrayEquals(Y1, Common.rev(X1));

		// null input
		try {
			Common.rev(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty array
		int[] X2 = {};
		int[] Y2 = {};
		assertArrayEquals(Y2, Common.rev(X2));

		// one element
		int[] X3 = { 5 };
		int[] Y3 = { 5 };
		assertArrayEquals(Y3, Common.rev(X3));

		// many elements
		int[] X4 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
				3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		int[] Y4 = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7,
				6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
		assertArrayEquals(Y4, Common.rev(X4));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#revb(byte[])}.
	 */
	@Test
	public void testRevb() {
		// example from NIST SP 800-38G
		byte[] X1 = { (byte) 1, (byte) 2, (byte) 3 };
		byte[] Y1 = { (byte) 3, (byte) 2, (byte) 1 };
		assertArrayEquals(Y1, Common.revb(X1));

		// null input
		try {
			Common.revb(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty array
		byte[] X2 = {};
		byte[] Y2 = {};
		assertArrayEquals(Y2, Common.revb(X2));

		// one element
		byte[] X3 = { 5 };
		byte[] Y3 = { 5 };
		assertArrayEquals(Y3, Common.revb(X3));

		// many elements
		byte[] X4 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
				3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		byte[] Y4 = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7,
				6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
		assertArrayEquals(Y4, Common.revb(X4));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#xor(byte[], byte[])}.
	 */
	@Test
	public void testXor() {
		// example from NIST SP 800-38G
		byte[] X1 = { (byte) 0x13 };
		byte[] Y1 = { (byte) 0x15 };
		byte[] Z1 = { (byte) 0x06 };
		assertArrayEquals(Z1, Common.xor(X1, Y1));

		// null input
		try {
			byte[] X = null;
			byte[] Y = { (byte) 0xA5 };
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			byte[] X = { (byte) 0x0F };
			byte[] Y = null;
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// mismatched length
		try {
			byte[] X = { (byte) 0x0F, (byte) 0xF0 };
			byte[] Y = { (byte) 0xA5 };
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// empty arrays
		try {
			byte[] X = {};
			byte[] Y = { (byte) 0xA5 };
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			byte[] X = { (byte) 0x0F };
			byte[] Y = {};
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// arrays too long
		try {
			byte[] X = new byte[Constants.MAXLEN + 1];
			byte[] Y = { (byte) 0xA5 };
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
		try {
			byte[] X = { (byte) 0x0F };
			byte[] Y = new byte[Constants.MAXLEN + 1];
			Common.xor(X, Y);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one element
		byte[] X2 = { (byte) 0x0F };
		byte[] Y2 = { (byte) 0xA5 };
		byte[] Z2 = { (byte) 0xAA };
		assertArrayEquals(Z2, Common.xor(X2, Y2));

		// many elements
		byte[] X3 = { (byte) 0x0F, (byte) 0xF0, (byte) 0xFF, (byte) 0x00 };
		byte[] Y3 = { (byte) 0xA5, (byte) 0xA5, (byte) 0xA5, (byte) 0xA5 };
		byte[] Z3 = { (byte) 0xAA, (byte) 0x55, (byte) 0x5A, (byte) 0xA5 };
		assertArrayEquals(Z3, Common.xor(X3, Y3));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#log2(int)}.
	 */
	@Test
	public void testLog2() {
		// examples from NIST SP 800-38G
		assertTrue(Common.log2(64) == 6);
		assertTrue(Common.log2(10) == Math.log(10) / Math.log(2));

		// negative
		try {
			Common.log2(-1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero
		try {
			Common.log2(0);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// integer result
		assertTrue(Common.log2(1024) == 10);

		// real result
		assertTrue(Common.log2(1023) < 10);
		assertTrue(Common.log2(1025) > 10);
	}

	/**
	 * Test method for {@link org.fpe4j.Common#floor(double)}.
	 */
	@Test
	public void testFloor() {
		// examples from NIST SP 800-38G
		assertEquals(2, Common.floor(2.1));
		assertEquals(4, Common.floor((double) 4));

		// correct usage
		assertEquals(2, Common.floor(7 / (double) 3));
		assertEquals(2, Common.floor(7 / 3.0));

		// incorrect usage
		try {
			assertEquals(2, Common.floor(7 / 3));
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// native integer division
		assertEquals(2, 7 / 3);
	}

	/**
	 * Test method for {@link org.fpe4j.Common#ceiling(double)}.
	 */
	@Test
	public void testCeiling() {
		// examples from NIST SP 800-38G
		assertEquals(3, Common.ceiling(2.1));
		assertEquals(4, Common.ceiling((double) 4));

		// correct usage
		assertEquals(3, Common.ceiling(7 / (double) 3));
		assertEquals(3, Common.ceiling(7 / 3.0));

		// incorrect usage
		try {
			assertEquals(3, Common.ceiling(7 / 3));
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}
	}

	/**
	 * Test method for {@link org.fpe4j.Common#mod(int, int)}.
	 */
	@Test
	public void testModIntInt() {
		// examples from NIST SP 800-38G
		assertEquals(4, Common.mod(-3, 7));
		assertEquals(6, Common.mod(13, 7));

		// equivalence to Math.floorMod()
		assertEquals(4, Math.floorMod(-3, 7));
		assertEquals(6, Math.floorMod(13, 7));

		// negative modulus
		try {
			Common.mod(13, -7);
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
			Common.mod(13, 0);
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
	 * Test method for {@link org.fpe4j.Common#mod(BigInteger, BigInteger)}.
	 */
	@Test
	public void testModBigIntegerBigInteger() {
		// examples from NIST SP 800-38G
		assertTrue(Common.mod(BigInteger.valueOf(-3), BigInteger.valueOf(7)).equals(BigInteger.valueOf(4)));
		assertTrue(Common.mod(BigInteger.valueOf(13), BigInteger.valueOf(7)).equals(BigInteger.valueOf(6)));

		// equivalence to BigInteger.mod()
		assertTrue(BigInteger.valueOf(-3).mod(BigInteger.valueOf(7)).equals(BigInteger.valueOf(4)));
		assertTrue(BigInteger.valueOf(13).mod(BigInteger.valueOf(7)).equals(BigInteger.valueOf(6)));

		// negative modulus
		try {
			Common.mod(BigInteger.valueOf(13), BigInteger.valueOf(-7));
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}
		try {
			BigInteger.valueOf(13).mod(BigInteger.valueOf(-7));
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}

		// zero modulus
		try {
			Common.mod(BigInteger.valueOf(13), BigInteger.ZERO);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}
		try {
			BigInteger.valueOf(13).mod(BigInteger.ZERO);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof ArithmeticException);
		}

	}

	/**
	 * Test method for {@link org.fpe4j.Common#bytestring(int, int)}.
	 */
	@Test
	public void testBytestringIntInt() {
		// example from NIST SP 800-38G
		byte[] expected1 = { (byte) 0x01 };
		assertArrayEquals(expected1, Common.bytestring(1, 1));

		// s too small
		try {
			Common.bytestring(1, -1);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// s too big
		try {
			Common.bytestring(1, Constants.MAXLEN + 1);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// x too small
		try {
			Common.bytestring(-1, 1);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// zero byte value
		byte[] expected2 = { };
		assertArrayEquals(expected2, Common.bytestring(0, 0));

		// one byte value
		byte[] expected3 = { (byte) 0xFF };
		assertArrayEquals(expected3, Common.bytestring(255, 1));

		// overflow one byte
		try {
			Common.bytestring(256, 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// two byte values
		byte[] expected4 = { (byte) 0x00, (byte) 0x01 };
		assertArrayEquals(expected4, Common.bytestring(1, 2));

		byte[] expected5 = { (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(expected5, Common.bytestring(65535, 2));

		// overflow two bytes
		try {
			Common.bytestring(65536, 2);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// extension to 16 bytes
		byte[] expected7 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x01 };
		assertArrayEquals(expected7, Common.bytestring(1, 16));

		byte[] expected8 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x7F, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF };
		assertArrayEquals(expected8, Common.bytestring(Integer.MAX_VALUE, 16));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#bytestring(BigInteger, int)}.
	 */
	@Test
	public void testBytestringBigIntegerInt() {
		// example from NIST SP 800-38G
		byte[] expected1 = { (byte) 0x01 };
		assertArrayEquals(expected1, Common.bytestring(BigInteger.ONE, 1));

		// s too small
		try {
			Common.bytestring(BigInteger.ONE, 0);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// x too small
		try {
			Common.bytestring(BigInteger.ONE.negate(), 1);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// one byte value
		byte[] expected2 = { (byte) 0xFF };
		assertArrayEquals(expected2, Common.bytestring(BigInteger.valueOf(255), 1));

		// overflow one byte
		try {
			Common.bytestring(BigInteger.valueOf(256), 1);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// two byte values
		byte[] expected4 = { (byte) 0x00, (byte) 0x01 };
		assertArrayEquals(expected4, Common.bytestring(BigInteger.ONE, 2));

		byte[] expected5 = { (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(expected5, Common.bytestring(BigInteger.valueOf(65535), 2));

		// overflow two bytes
		try {
			Common.bytestring(BigInteger.valueOf(65536), 2);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// extension to 16 byte values
		byte[] expected7 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x01 };
		assertArrayEquals(expected7, Common.bytestring(BigInteger.ONE, 16));

		byte[] expected8 = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x7F, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF };
		assertArrayEquals(expected8, Common.bytestring(BigInteger.valueOf(Integer.MAX_VALUE), 16));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#bitstring(boolean, int)}.
	 */
	@Test
	public void testBitstring() {
		// example from NIST SP 800-38G
		byte[] expected1 = { (byte) 0 };
		assertArrayEquals(expected1, Common.bitstring(false, 8));

		// s is negative
		try {
			Common.bitstring(false, -8);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// s is not a multiple of 8
		try {
			Common.bitstring(false, 4);
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// two byte values
		byte[] expected2 = { (byte) 0, (byte) 0 };
		assertArrayEquals(expected2, Common.bitstring(false, 16));
		byte[] expected3 = { (byte) 0xFF, (byte) 0xFF };
		assertArrayEquals(expected3, Common.bitstring(true, 16));

		// 16 byte values
		byte[] expected4 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		assertArrayEquals(expected4, Common.bitstring(false, 128));
		byte[] expected5 = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF };
		assertArrayEquals(expected5, Common.bitstring(true, 128));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#concatenate(int[], int[])}.
	 */
	@Test
	public void testConcatenateIntArrayIntArray() {
		// example from NIST SP 800-38G
		int[] X1 = { 3, 1 };
		int[] Y1 = { 31, 8, 10 };
		int[] Z1 = { 3, 1, 31, 8, 10 };
		assertArrayEquals(Z1, Common.concatenate(X1, Y1));

		// null input
		try {
			int[] X = { 1, 2, 3 };
			Common.concatenate(X, null);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			int[] Y = { 4, 5, 6 };
			Common.concatenate(null, Y);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		int[] X2 = { 1, 2, 3 };
		int[] Y2 = {};
		int[] Z2 = { 1, 2, 3 };
		assertArrayEquals(Z2, Common.concatenate(X2, Y2));
		int[] X3 = {};
		int[] Y3 = { 4, 5, 6 };
		int[] Z3 = { 4, 5, 6 };
		assertArrayEquals(Z3, Common.concatenate(X3, Y3));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#concatenate(byte[], byte[])}.
	 */
	@Test
	public void testConcatenateByteArrayByteArray() {
		// example from NIST SP 800-38G
		byte[] X1 = { 3, 1 };
		byte[] Y1 = { 31, 8, 10 };
		byte[] Z1 = { 3, 1, 31, 8, 10 };
		assertArrayEquals(Z1, Common.concatenate(X1, Y1));

		// null input
		try {
			byte[] X = { 1, 2, 3 };
			Common.concatenate(X, null);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}
		try {
			byte[] Y = { 4, 5, 6 };
			Common.concatenate(null, Y);
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		byte[] X2 = { 1, 2, 3 };
		byte[] Y2 = {};
		byte[] Z2 = { 1, 2, 3 };
		assertArrayEquals(Z2, Common.concatenate(X2, Y2));
		byte[] X3 = {};
		byte[] Y3 = { 4, 5, 6 };
		byte[] Z3 = { 4, 5, 6 };
		assertArrayEquals(Z3, Common.concatenate(X3, Y3));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#intArrayToString(int[])}.
	 */
	@Test
	public void testIntArrayToString() {
		// null input
		try {
			Common.intArrayToString(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		int[] X1 = {};
		assertEquals("", Common.intArrayToString(X1));

		// one element
		int[] X2 = { 1 };
		assertEquals("1", Common.intArrayToString(X2));

		// many elements
		int[] X3 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
				3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		assertEquals(
				"0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9",
				Common.intArrayToString(X3));
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.Common#unsignedByteArrayToString(byte[])}.
	 */
	@Test
	public void testUnsignedByteArrayToString() {
		// null input
		try {
			Common.unsignedByteArrayToString(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		byte[] X1 = {};
		assertEquals("[ ]", Common.unsignedByteArrayToString(X1));

		// one element
		byte[] X2 = { 1 };
		assertEquals("[ 1 ]", Common.unsignedByteArrayToString(X2));

		// many elements
		byte[] X3 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
				3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		assertEquals(
				"[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ]",
				Common.unsignedByteArrayToString(X3));

		// range of values
		byte[] X4 = { (byte) 0x00, (byte) 0x7F, (byte) 0x80, (byte) 0xFF };
		assertEquals("[ 0, 127, 128, 255 ]", Common.unsignedByteArrayToString(X4));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#byteArrayToHexString(byte[])}.
	 */
	@Test
	public void testByteArrayToHexString() {
		// null input
		try {
			Common.byteArrayToHexString(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		byte[] X1 = {};
		assertEquals("", Common.byteArrayToHexString(X1));

		// one element
		byte[] X2 = { 1 };
		assertEquals("01", Common.byteArrayToHexString(X2));

		// many elements
		byte[] X3 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2,
				3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		assertEquals(
				"000102030405060708090001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809",
				Common.byteArrayToHexString(X3));

		// range of values
		byte[] X4 = { (byte) 0x00, (byte) 0x7F, (byte) 0x80, (byte) 0xFF };
		assertEquals("007F80FF", Common.byteArrayToHexString(X4));
	}

	/**
	 * Test method for {@link org.fpe4j.Common#hexStringToByteArray(String)}.
	 */
	@Test
	public void testHexStringToByteArray() {
		// null input
		try {
			Common.hexStringToByteArray(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		byte[] expected1 = {};
		assertArrayEquals(expected1, Common.hexStringToByteArray(""));

		// odd length
		try {
			Common.hexStringToByteArray("AAB");
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// invalid character
		try {
			Common.hexStringToByteArray("ABCDEFGH");
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// range of values
		for (int i = 0; i < 16; i++) {
			byte[] b = { (byte) (i * 16), (byte) (i * 16 + 1), (byte) (i * 16 + 2), (byte) (i * 16 + 3),
					(byte) (i * 16 + 4), (byte) (i * 16 + 5), (byte) (i * 16 + 6), (byte) (i * 16 + 7),
					(byte) (i * 16 + 8), (byte) (i * 16 + 9), (byte) (i * 16 + 10), (byte) (i * 16 + 11),
					(byte) (i * 16 + 12), (byte) (i * 16 + 13), (byte) (i * 16 + 14), (byte) (i * 16 + 15) };
			String s = Common.byteArrayToHexString(b);
			assertArrayEquals(b, Common.hexStringToByteArray(s));
		}
	}

	/**
	 * Test method for {@link org.fpe4j.Common#intStringToIntArray(String)}
	 */
	@Test
	public void testIntStringToIntArray() {
		// null input
		try {
			Common.intStringToIntArray(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		int[] expected1 = {};
		assertArrayEquals(expected1, Common.intStringToIntArray(""));

		// leading non-numeric characters
		int[] expected2 = { 10, 11 };
		assertArrayEquals(expected2, Common.intStringToIntArray(" 10 11"));

		// trailing non-numeric characters
		int[] expected3 = { 12, 13 };
		assertArrayEquals(expected3, Common.intStringToIntArray("12 13 "));

		// no numeric characters
		int[] expected4 = {};
		assertArrayEquals(expected4, Common.intStringToIntArray("asdfjkl;"));

		// range of values
		int[] expected5 = { 0, 1, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };
		assertArrayEquals(expected5, Common.intStringToIntArray("0, 1, 2147483647, -2147483648, -1"));

	}
}
