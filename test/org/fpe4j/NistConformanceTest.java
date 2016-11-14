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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;

import javax.crypto.spec.SecretKeySpec;

import org.fpe4j.utilities.Utilities;
import org.junit.Test;

/**
 * JUnit test cases for conformance with the NIST sample data provided at
 * <a href=
 * "http://csrc.nist.gov/groups/ST/toolkit/examples.html">http://csrc.nist.gov/groups/ST/toolkit/examples.html</a>.
 * <p>
 * To enable FF1 and FF3 to output the intermediate results shown in the sample
 * data, change {@link org.fpe4j.Constants#CONFORMANCE_OUTPUT} to true.
 * 
 * @author Kai Johnson
 *
 */
public class NistConformanceTest {

	/**
	 * Input parameters for a single test case.
	 * 
	 * @author Kai Johnson
	 *
	 */
	private class TestInput {

		final String name;
		final int radix;
		final byte[] key;
		final byte[] tweak;
		final int[] plaintext;
		final int[] ciphertext;

		/**
		 * Constructs a TestInput instance with the specified test parameters.
		 * 
		 * @param name
		 *            the name of the test case
		 * @param radix
		 *            the radix for FPE operations
		 * @param key
		 *            the raw key data for FPE operations
		 * @param tweak
		 *            the tweak for FPE operations
		 * @param plaintext
		 *            the original plaintext and expected result of decrypting
		 *            the ciphertext
		 * @param ciphertext
		 *            the original ciphertext and expected result of encrypting
		 *            the plaintext
		 */
		TestInput(String name, int radix, byte[] key, byte[] tweak, int[] plaintext, int[] ciphertext) {
			this.name = name;
			this.radix = radix;
			this.key = key;
			this.tweak = tweak;
			this.plaintext = plaintext;
			this.ciphertext = ciphertext;
		}
	}

	/**
	 * Test {@link org.fpe4j.FF1} for conformance with the NIST sample data.
	 */
	@Test
	public void testFF1Conformance() {

		// set up the test inputs
		TestInput[] ff1Tests = {
				// Sample #1
				new TestInput("Sample #1", 10, Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray(""), Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("2 4 3 3 4 7 7 4 8 4")),
				// Sample #2
				new TestInput("Sample #2", 10, Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("39383736353433323130"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("6 1 2 4 2 0 0 7 7 3")),
				// Sample #3
				new TestInput("Sample #3", 36, Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("3737373770717273373737"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18"),
						Utilities.intStringToIntArray("10 9 29 31 4 0 22 21 21 9 20 13 30 5 0 9 14 30 22")),
				// Sample #4
				new TestInput("Sample #4", 10,
						Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
						Utilities.hexStringToByteArray(""), Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("2 8 3 0 6 6 8 1 3 2")),
				// Sample #5
				new TestInput("Sample #5", 10,
						Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
						Utilities.hexStringToByteArray("39383736353433323130"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("2 4 9 6 6 5 5 5 4 9")),
				// Sample #6
				new TestInput("Sample #6", 10,
						Utilities.hexStringToByteArray("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
						Utilities.hexStringToByteArray("39383736353433323130"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("2 4 9 6 6 5 5 5 4 9")),
				// Sample #7
				new TestInput("Sample #7", 10,
						Utilities.hexStringToByteArray(
								"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray(""), Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("6 6 5 7 6 6 7 0 0 9")),
				// Sample #8
				new TestInput("Sample #8", 10,
						Utilities.hexStringToByteArray(
								"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("39383736353433323130"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9"),
						Utilities.intStringToIntArray("1 0 0 1 6 2 3 4 6 3")),
				// Sample #9
				new TestInput("Sample #9", 36,
						Utilities.hexStringToByteArray(
								"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("3737373770717273373737"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18"),
						Utilities.intStringToIntArray("33 28 8 10 0 10 35 17 2 10 31 34 10 21 34 35 30 32 13")),
				// Test Concatenation in Step 6. iii.
				new TestInput("Test Concatenation in Step 6. iii.", 256,
						Utilities.hexStringToByteArray(
								"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("3737373770717273373737"),
						Utilities.intStringToIntArray(
								"77 104 140 63 156 241 168 217 77 120 141 248 199 103 250 164 56 175 134 207 120 221 126 109 156 169 100 89 115 18 217 150 78 71 81 206 168 98 98 156 95 122 38 63 68 30 212 125 250 155 29 218 189 20 234 97 130 113 229 168 221 55 161 90 45 240 130 241 58 61 170 204 41 160 144 147 174 65 87 23"),
						Utilities.intStringToIntArray(
								"68 111 39 159 6 189 255 68 203 183 154 249 35 48 199 152 118 215 63 117 164 44 164 195 236 192 41 33 25 92 8 156 151 239 253 22 223 23 228 167 170 8 34 25 11 181 38 5 111 145 154 135 59 238 62 185 132 63 216 218 107 179 121 95 87 20 239 2 80 133 216 171 142 192 139 64 105 203 160 125")),
				//
		};

		// for each test input
		for (TestInput test : ff1Tests) {
			try {
				// create an FF1 instance
				FF1 ff1 = new FF1(test.radix, Constants.MAXLEN);
				assertNotNull(ff1);

				// create an AES key from the key data
				SecretKeySpec K = new SecretKeySpec(test.key, "AES");

				System.out.println("\n==============================================================\n");
				System.out.println(test.name + "\n");
				System.out.println("FF1-AES" + test.key.length * 8 + "\n");
				System.out.println("Key is " + Common.byteArrayToHexString(test.key));
				System.out.println("Radix = " + test.radix);
				System.out.println("--------------------------------------------------------------\n");
				System.out.println("PT is <" + Common.intArrayToString(test.plaintext) + ">\n");

				// perform the encryption
				int[] CT = ff1.encrypt(K, test.tweak, test.plaintext);

				System.out.println("CT is <" + Common.intArrayToString(CT) + ">");

				// validate the ciphertext
				assertArrayEquals(test.ciphertext, CT);

				System.out.println("\n--------------------------------------------------------------\n");

				// perform the decryption
				int[] PT = ff1.decrypt(K, test.tweak, CT);

				System.out.println("PT is <" + Common.intArrayToString(PT) + ">");

				// validate the recovered plaintext
				assertArrayEquals(test.plaintext, PT);
			} catch (InvalidKeyException e) {
				fail(e.toString());
			}
		}
	}

	/**
	 * Test {@link org.fpe4j.FF3} for conformance with the NIST sample data.
	 */
	@Test
	public void testFF3Conformance() {

		// set up the test inputs
		TestInput[] ff3Tests = {
				// Sample #1
				new TestInput("Sample #1", 10, Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("D8E7920AFA330A73"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0"),
						Utilities.intStringToIntArray("7 5 0 9 1 8 8 1 4 0 5 8 6 5 4 6 0 7")),
				// Sample #2
				new TestInput("Sample #2", 10, Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("9A768A92F60E12D8"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0"),
						Utilities.intStringToIntArray("0 1 8 9 8 9 8 3 9 1 8 9 3 9 5 3 8 4")),
				// Sample #3
				new TestInput("Sample #3", 10, Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("D8E7920AFA330A73"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 7 8 9 0 0 0 0 0 0"),
						Utilities.intStringToIntArray("4 8 5 9 8 3 6 7 1 6 2 2 5 2 5 6 9 6 2 9 3 9 7 4 1 6 2 2 6")),
				// Sample #4
				new TestInput("Sample #4", 10, Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("0000000000000000"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 7 8 9 0 0 0 0 0 0"),
						Utilities.intStringToIntArray("3 4 6 9 5 2 2 4 8 2 1 7 3 4 5 3 5 1 2 2 6 1 3 7 0 1 4 3 4")),
				// Sample #5
				new TestInput("Sample #5", 26, Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A94"),
						Utilities.hexStringToByteArray("9A768A92F60E12D8"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18"),
						Utilities.intStringToIntArray("16 2 25 20 4 0 18 9 9 2 15 23 2 0 12 19 10 20 11")),
				// Sample #6
				new TestInput("Sample #6", 10,
						Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6"),
						Utilities.hexStringToByteArray("D8E7920AFA330A73"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0"),
						Utilities.intStringToIntArray("6 4 6 9 6 5 3 9 3 8 7 5 0 2 8 7 5 5")),
				// Sample #7
				new TestInput("Sample #7", 10,
						Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6"),
						Utilities.hexStringToByteArray("9A768A92F60E12D8"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0"),
						Utilities.intStringToIntArray("9 6 1 6 1 0 5 1 4 4 9 1 4 2 4 4 4 6")),
				// Sample #8
				new TestInput("Sample #8", 10,
						Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6"),
						Utilities.hexStringToByteArray("D8E7920AFA330A73"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 7 8 9 0 0 0 0 0 0"),
						Utilities.intStringToIntArray("5 3 0 4 8 8 8 4 0 6 5 3 5 0 2 0 4 5 4 1 7 8 6 3 8 0 8 0 7")),
				// Sample #9
				new TestInput("Sample #9", 10,
						Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6"),
						Utilities.hexStringToByteArray("0000000000000000"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 7 8 9 0 0 0 0 0 0"),
						Utilities.intStringToIntArray("9 8 0 8 3 8 0 2 6 7 8 8 2 0 3 8 9 2 9 5 0 4 1 4 8 3 5 1 2")),
				// Sample #10
				new TestInput("Sample #10", 26,
						Utilities.hexStringToByteArray("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6"),
						Utilities.hexStringToByteArray("9A768A92F60E12D8"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18"),
						Utilities.intStringToIntArray("18 0 18 17 14 2 19 15 19 7 10 9 24 25 15 9 25 8 8")),
				// Sample #11
				new TestInput("Sample #11", 10,
						Utilities.hexStringToByteArray(
								"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("D8E7920AFA330A73"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0"),
						Utilities.intStringToIntArray("9 2 2 0 1 1 2 0 5 5 6 2 7 7 7 4 9 5")),
				// Sample #12
				new TestInput("Sample #12", 10,
						Utilities.hexStringToByteArray(
								"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("9A768A92F60E12D8"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0"),
						Utilities.intStringToIntArray("5 0 4 1 4 9 8 6 5 5 7 8 0 5 6 1 4 0")),
				// Sample #13
				new TestInput("Sample #13", 10,
						Utilities.hexStringToByteArray(
								"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("D8E7920AFA330A73"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 7 8 9 0 0 0 0 0 0"),
						Utilities.intStringToIntArray("0 4 3 4 4 3 4 3 2 3 5 7 9 2 5 9 9 1 6 5 7 3 4 6 2 2 6 9 9")),
				// Sample #14
				new TestInput("Sample #14", 10,
						Utilities.hexStringToByteArray(
								"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("0000000000000000"),
						Utilities.intStringToIntArray("8 9 0 1 2 1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 7 8 9 0 0 0 0 0 0"),
						Utilities.intStringToIntArray("3 0 8 5 9 2 3 9 9 9 9 3 7 4 0 5 3 8 7 2 3 6 5 5 5 5 8 2 2")),
				// Sample #15
				new TestInput("Sample #15", 26,
						Utilities.hexStringToByteArray(
								"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C"),
						Utilities.hexStringToByteArray("9A768A92F60E12D8"),
						Utilities.intStringToIntArray("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18"),
						Utilities.intStringToIntArray("25 0 11 2 16 24 13 15 19 10 9 11 17 11 7 11 20 3 8")),
				//
		};

		// for each test input
		for (TestInput test : ff3Tests) {
			try {
				// create an FF3 instance
				FF3 ff3 = new FF3(test.radix);
				assertNotNull(ff3);

				// create an AES key from the key data
				SecretKeySpec K = new SecretKeySpec(test.key, "AES");

				System.out.println("\n==============================================================\n");
				System.out.println(test.name + "\n");
				System.out.println("FF3-AES" + test.key.length * 8 + "\n");
				System.out.println("Key is " + Common.byteArrayToHexString(test.key));
				System.out.println("Radix = " + test.radix);
				System.out.println("--------------------------------------------------------------\n");
				System.out.println("PT is <" + Common.intArrayToString(test.plaintext) + ">\n");

				// perform the encryption
				int[] CT = ff3.encrypt(K, test.tweak, test.plaintext);

				System.out.println("CT is <" + Common.intArrayToString(CT) + ">");

				// validate the ciphertext
				assertArrayEquals(test.ciphertext, CT);

				System.out.println("\n--------------------------------------------------------------\n");

				// perform the decryption
				int[] PT = ff3.decrypt(K, test.tweak, test.ciphertext);

				System.out.println("PT is <" + Common.intArrayToString(PT) + ">");

				// validate the recovered plaintext
				assertArrayEquals(test.plaintext, PT);
			} catch (InvalidKeyException e) {
				fail(e.toString());
			}
		}
	}
}
