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
package org.fpe4j.utilities;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Test methods for Utilities class.
 * 
 * @author Kai Johnson
 *
 */
public class UtilitiesTest {

	/**
	 * Test method for
	 * {@link org.fpe4j.utilities.Utilities#hexStringToByteArray(String)}.
	 */
	@Test
	public void testHexStringToByteArray() {
		// null input
		try {
			Utilities.hexStringToByteArray(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		byte[] expected1 = {};
		assertArrayEquals(expected1, Utilities.hexStringToByteArray(""));

		// odd length
		try {
			Utilities.hexStringToByteArray("AAB");
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// invalid character
		try {
			Utilities.hexStringToByteArray("ABCDEFGH");
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
		}

		// range of values
		String[] H = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", };
		for (int i = 0; i < 16; i++) {
			for (int j = 0; j < 16; j++) {
				byte[] b = { (byte) (i * 16 + j) };
				String s = H[i] + H[j];
				assertArrayEquals(b, Utilities.hexStringToByteArray(s));
			}
		}
	}

	/**
	 * Test method for
	 * {@link org.fpe4j.utilities.Utilities#intStringToIntArray(String)}
	 */
	@Test
	public void testIntStringToIntArray() {
		// null input
		try {
			Utilities.intStringToIntArray(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof NullPointerException);
		}

		// empty input
		int[] expected1 = {};
		assertArrayEquals(expected1, Utilities.intStringToIntArray(""));

		// leading non-numeric characters
		int[] expected2 = { 10, 11 };
		assertArrayEquals(expected2, Utilities.intStringToIntArray(" 10 11"));

		// trailing non-numeric characters
		int[] expected3 = { 12, 13 };
		assertArrayEquals(expected3, Utilities.intStringToIntArray("12 13 "));

		// no numeric characters
		int[] expected4 = {};
		assertArrayEquals(expected4, Utilities.intStringToIntArray("asdfjkl;"));

		// range of values
		int[] expected5 = { 0, 1, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };
		assertArrayEquals(expected5, Utilities.intStringToIntArray("0, 1, 2147483647, -2147483648, -1"));

	}

	/**
	 * Test method for {@link org.fpe4j.utilities.Utilities#Utilities()}.
	 */
	@Test
	public void testUtilities() {
		try {
			new Utilities();
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof RuntimeException);
		}
	}
}
