/**
 * 
 */
package org.fpe4j;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

/**
 * JUnit test cases for conformance with the NIST sample data provided at
 * <a href=
 * "http://csrc.nist.gov/groups/ST/toolkit/examples.html">http://csrc.nist.gov/groups/ST/toolkit/examples.html</a>.
 * <p>
 * To allow FF1 and FF3 to output the intermediate results shown in the sample
 * data, change {@link org.fpe4j.Constants#CONFORMANCE_OUTPUT} to
 * true.
 * 
 * @author Kai Johnson
 *
 */
public class ConformanceTest {

	/**
	 * Test {@link org.fpe4j.FF1} for conformance with the NIST
	 * sample data.
	 */
	@Test
	public void testFF1Conformance() {
		try {
			// initialize prerequisites from the sample data
			int radix = 10;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = {};

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
			int[] ciphertext = { 2, 4, 3, 3, 4, 7, 7, 4, 8, 4 };

			testFF1Iteration("Sample #1", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 10;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x39, (byte) 0x38, (byte) 0x37, (byte) 0x36, (byte) 0x35, (byte) 0x34, (byte) 0x33,
					(byte) 0x32, (byte) 0x31, (byte) 0x30 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
			int[] ciphertext = { 6, 1, 2, 4, 2, 0, 0, 7, 7, 3 };

			testFF1Iteration("Sample #2", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 36;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x70, (byte) 0x71, (byte) 0x72,
					(byte) 0x73, (byte) 0x37, (byte) 0x37, (byte) 0x37 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
			int[] ciphertext = { 10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22 };

			testFF1Iteration("Sample #3", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 10;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F };

			// initialize the tweak from the sample data
			byte[] tweak = {};

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
			int[] ciphertext = { 2, 8, 3, 0, 6, 6, 8, 1, 3, 2 };

			testFF1Iteration("Sample #4", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 10;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x39, (byte) 0x38, (byte) 0x37, (byte) 0x36, (byte) 0x35, (byte) 0x34, (byte) 0x33,
					(byte) 0x32, (byte) 0x31, (byte) 0x30 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
			int[] ciphertext = { 2, 4, 9, 6, 6, 5, 5, 5, 4, 9 };

			testFF1Iteration("Sample #5", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 36;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x70, (byte) 0x71, (byte) 0x72,
					(byte) 0x73, (byte) 0x37, (byte) 0x37, (byte) 0x37 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
			int[] ciphertext = { 33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27 };

			testFF1Iteration("Sample #6", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 10;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F,
					(byte) 0x04, (byte) 0xFC, (byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = {};

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
			int[] ciphertext = { 6, 6, 5, 7, 6, 6, 7, 0, 0, 9 };

			testFF1Iteration("Sample #7", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 10;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F,
					(byte) 0x04, (byte) 0xFC, (byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x39, (byte) 0x38, (byte) 0x37, (byte) 0x36, (byte) 0x35, (byte) 0x34, (byte) 0x33,
					(byte) 0x32, (byte) 0x31, (byte) 0x30 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
			int[] ciphertext = { 1, 0, 0, 1, 6, 2, 3, 4, 6, 3 };

			testFF1Iteration("Sample #8", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 36;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F,
					(byte) 0x04, (byte) 0xFC, (byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x70, (byte) 0x71, (byte) 0x72,
					(byte) 0x73, (byte) 0x37, (byte) 0x37, (byte) 0x37 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
			int[] ciphertext = { 33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13 };

			testFF1Iteration("Sample #9", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		try {
			// initialize prerequisites from the sample data
			int radix = 256;
			int maxTlen = 256;

			// initialize the key with the sample data
			byte[] key = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
					(byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xCF,
					(byte) 0x4F, (byte) 0x3C, (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5,
					(byte) 0x80, (byte) 0xAA, (byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F,
					(byte) 0x04, (byte) 0xFC, (byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x37, (byte) 0x70, (byte) 0x71, (byte) 0x72,
					(byte) 0x73, (byte) 0x37, (byte) 0x37, (byte) 0x37 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 77, 104, 140, 63, 156, 241, 168, 217, 77, 120, 141, 248, 199, 103, 250, 164, 56, 175,
					134, 207, 120, 221, 126, 109, 156, 169, 100, 89, 115, 18, 217, 150, 78, 71, 81, 206, 168, 98, 98,
					156, 95, 122, 38, 63, 68, 30, 212, 125, 250, 155, 29, 218, 189, 20, 234, 97, 130, 113, 229, 168,
					221, 55, 161, 90, 45, 240, 130, 241, 58, 61, 170, 204, 41, 160, 144, 147, 174, 65, 87, 23 };
			int[] ciphertext = { 68, 111, 39, 159, 6, 189, 255, 68, 203, 183, 154, 249, 35, 48, 199, 152, 118, 215, 63,
					117, 164, 44, 164, 195, 236, 192, 41, 33, 25, 92, 8, 156, 151, 239, 253, 22, 223, 23, 228, 167, 170,
					8, 34, 25, 11, 181, 38, 5, 111, 145, 154, 135, 59, 238, 62, 185, 132, 63, 216, 218, 107, 179, 121,
					95, 87, 20, 239, 2, 80, 133, 216, 171, 142, 192, 139, 64, 105, 203, 160, 125 };

			testFF1Iteration("Test Concatenation in Step 6. iii.", radix, maxTlen, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}
	}

	/**
	 * Perform a single test of FF1 encryption and decryption.
	 * 
	 * @param name
	 *            The name of the test.
	 * @param radix
	 *            The radix used in plaintext and ciphertext arguments.
	 * @param maxTlen
	 *            The maximum length of a tweak.
	 * @param key
	 *            The AES key.
	 * @param tweak
	 *            The tweak.
	 * @param plaintext
	 *            The plaintext input.
	 * @param ciphertext
	 *            The expected ciphertext output.
	 * @throws InvalidKeyException
	 *             Only if there's a programming error.
	 */
	private void testFF1Iteration(String name, int radix, int maxTlen, byte[] key, byte[] tweak, int[] plaintext,
			int[] ciphertext) throws InvalidKeyException {

		// create an FF1 instance
		FF1 ff1 = new FF1(radix, maxTlen);
		assertNotNull(ff1);

		// create an AES key from the key data
		SecretKeySpec K = new SecretKeySpec(key, "AES");

		System.out.println("\n==============================================================\n");
		System.out.println(name + "\n");
		System.out.println("FF1-AES" + key.length * 8 + "\n");
		System.out.println("Key is " + Common.byteArrayToHexString(key));
		System.out.println("Radix = " + radix);
		System.out.println("--------------------------------------------------------------\n");
		System.out.println("PT is <" + Common.intArrayToString(plaintext) + ">\n");

		// perform the encryption
		int[] CT = ff1.encrypt(K, tweak, plaintext);

		System.out.println("CT is <" + Common.intArrayToString(CT) + ">");

		// validate the ciphertext
		assertArrayEquals(ciphertext, CT);

		System.out.println("\n--------------------------------------------------------------\n");

		// perform the decryption
		int[] PT = ff1.decrypt(K, tweak, CT);

		System.out.println("PT is <" + Common.intArrayToString(PT) + ">");

		// validate the recovered plaintext
		assertArrayEquals(plaintext, PT);
	}

	/**
	 * Test {@link org.fpe4j.FF3} for conformance with the NIST
	 * sample data.
	 */
	@Test
	public void testFF3Conformance() {

		// Sample #1
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0xD8, (byte) 0xE7, (byte) 0x92, (byte) 0x0A, (byte) 0xFA, (byte) 0x33, (byte) 0x0A,
					(byte) 0x73 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0 };
			int[] ciphertext = { 7, 5, 0, 9, 1, 8, 8, 1, 4, 0, 5, 8, 6, 5, 4, 6, 0, 7 };

			testFF3Iteration("Sample #1", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #2
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x9A, (byte) 0x76, (byte) 0x8A, (byte) 0x92, (byte) 0xF6, (byte) 0x0E, (byte) 0x12,
					(byte) 0xD8 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0 };
			int[] ciphertext = { 0, 1, 8, 9, 8, 9, 8, 3, 9, 1, 8, 9, 3, 9, 5, 3, 8, 4 };

			testFF3Iteration("Sample #2", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #3
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0xD8, (byte) 0xE7, (byte) 0x92, (byte) 0x0A, (byte) 0xFA, (byte) 0x33, (byte) 0x0A,
					(byte) 0x73 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
			int[] ciphertext = { 4, 8, 5, 9, 8, 3, 6, 7, 1, 6, 2, 2, 5, 2, 5, 6, 9, 6, 2, 9, 3, 9, 7, 4, 1, 6, 2, 2,
					6 };

			testFF3Iteration("Sample #3", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #4
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
					(byte) 0x00 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
			int[] ciphertext = { 3, 4, 6, 9, 5, 2, 2, 4, 8, 2, 1, 7, 3, 4, 5, 3, 5, 1, 2, 2, 6, 1, 3, 7, 0, 1, 4, 3,
					4 };

			testFF3Iteration("Sample #4", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #5
		try {
			// initialize prerequisites from the sample data
			int radix = 26;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x9A, (byte) 0x76, (byte) 0x8A, (byte) 0x92, (byte) 0xF6, (byte) 0x0E, (byte) 0x12,
					(byte) 0xD8 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
			int[] ciphertext = { 16, 2, 25, 20, 4, 0, 18, 9, 9, 2, 15, 23, 2, 0, 12, 19, 10, 20, 11 };

			testFF3Iteration("Sample #5", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #6
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0xD8, (byte) 0xE7, (byte) 0x92, (byte) 0x0A, (byte) 0xFA, (byte) 0x33, (byte) 0x0A,
					(byte) 0x73 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0 };
			int[] ciphertext = { 6, 4, 6, 9, 6, 5, 3, 9, 3, 8, 7, 5, 0, 2, 8, 7, 5, 5 };

			testFF3Iteration("Sample #6", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #7
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x9A, (byte) 0x76, (byte) 0x8A, (byte) 0x92, (byte) 0xF6, (byte) 0x0E, (byte) 0x12,
					(byte) 0xD8 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0 };
			int[] ciphertext = { 9, 6, 1, 6, 1, 0, 5, 1, 4, 4, 9, 1, 4, 2, 4, 4, 4, 6 };

			testFF3Iteration("Sample #7", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #8
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0xD8, (byte) 0xE7, (byte) 0x92, (byte) 0x0A, (byte) 0xFA, (byte) 0x33, (byte) 0x0A,
					(byte) 0x73 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
			int[] ciphertext = { 5, 3, 0, 4, 8, 8, 8, 4, 0, 6, 5, 3, 5, 0, 2, 0, 4, 5, 4, 1, 7, 8, 6, 3, 8, 0, 8, 0,
					7 };

			testFF3Iteration("Sample #8", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #9
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
					(byte) 0x00 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
			int[] ciphertext = { 9, 8, 0, 8, 3, 8, 0, 2, 6, 7, 8, 8, 2, 0, 3, 8, 9, 2, 9, 5, 0, 4, 1, 4, 8, 3, 5, 1,
					2 };

			testFF3Iteration("Sample #9", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #10
		try {
			// initialize prerequisites from the sample data
			int radix = 26;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6 };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x9A, (byte) 0x76, (byte) 0x8A, (byte) 0x92, (byte) 0xF6, (byte) 0x0E, (byte) 0x12,
					(byte) 0xD8 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
			int[] ciphertext = { 18, 0, 18, 17, 14, 2, 19, 15, 19, 7, 10, 9, 24, 25, 15, 9, 25, 8, 8 };

			testFF3Iteration("Sample #10", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #11
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
					(byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0xD8, (byte) 0xE7, (byte) 0x92, (byte) 0x0A, (byte) 0xFA, (byte) 0x33, (byte) 0x0A,
					(byte) 0x73 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0 };
			int[] ciphertext = { 9, 2, 2, 0, 1, 1, 2, 0, 5, 5, 6, 2, 7, 7, 7, 4, 9, 5 };

			testFF3Iteration("Sample #11", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #12
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
					(byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x9A, (byte) 0x76, (byte) 0x8A, (byte) 0x92, (byte) 0xF6, (byte) 0x0E, (byte) 0x12,
					(byte) 0xD8 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0 };
			int[] ciphertext = { 5, 0, 4, 1, 4, 9, 8, 6, 5, 5, 7, 8, 0, 5, 6, 1, 4, 0 };

			testFF3Iteration("Sample #12", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #13
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
					(byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0xD8, (byte) 0xE7, (byte) 0x92, (byte) 0x0A, (byte) 0xFA, (byte) 0x33, (byte) 0x0A,
					(byte) 0x73 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
			int[] ciphertext = { 0, 4, 3, 4, 4, 3, 4, 3, 2, 3, 5, 7, 9, 2, 5, 9, 9, 1, 6, 5, 7, 3, 4, 6, 2, 2, 6, 9,
					9 };

			testFF3Iteration("Sample #13", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #14
		try {
			// initialize prerequisites from the sample data
			int radix = 10;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
					(byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
					(byte) 0x00 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 7, 8, 9, 0, 0, 0, 0, 0, 0 };
			int[] ciphertext = { 3, 0, 8, 5, 9, 2, 3, 9, 9, 9, 9, 3, 7, 4, 0, 5, 3, 8, 7, 2, 3, 6, 5, 5, 5, 5, 8, 2,
					2 };

			testFF3Iteration("Sample #14", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}

		// Sample #15
		try {
			// initialize prerequisites from the sample data
			int radix = 26;

			// initialize the key with the sample data
			byte[] key = { (byte) 0xEF, (byte) 0x43, (byte) 0x59, (byte) 0xD8, (byte) 0xD5, (byte) 0x80, (byte) 0xAA,
					(byte) 0x4F, (byte) 0x7F, (byte) 0x03, (byte) 0x6D, (byte) 0x6F, (byte) 0x04, (byte) 0xFC,
					(byte) 0x6A, (byte) 0x94, (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28,
					(byte) 0xAE, (byte) 0xD2, (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
					(byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C };

			// initialize the tweak from the sample data
			byte[] tweak = { (byte) 0x9A, (byte) 0x76, (byte) 0x8A, (byte) 0x92, (byte) 0xF6, (byte) 0x0E, (byte) 0x12,
					(byte) 0xD8 };

			// initialize plaintext and ciphertext values from the sample data
			int[] plaintext = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
			int[] ciphertext = { 25, 0, 11, 2, 16, 24, 13, 15, 19, 10, 9, 11, 17, 11, 7, 11, 20, 3, 8 };

			testFF3Iteration("Sample #15", radix, key, tweak, plaintext, ciphertext);
		} catch (InvalidKeyException e) {
			fail();
		}
	}

	/**
	 * Perform a single test of FF3 encryption and decryption.
	 * 
	 * @param name
	 *            The name of the test.
	 * @param radix
	 *            The radix used in plaintext and ciphertext arguments.
	 * @param key
	 *            The AES key.
	 * @param tweak
	 *            The tweak.
	 * @param plaintext
	 *            The plaintext input.
	 * @param ciphertext
	 *            The expected ciphertext output.
	 * @throws InvalidKeyException
	 *             Only if there's a programming error.
	 */
	private void testFF3Iteration(String name, int radix, byte[] key, byte[] tweak, int[] plaintext, int[] ciphertext)
			throws InvalidKeyException {

		// create an FF3 instance
		FF3 ff3 = new FF3(radix);
		assertNotNull(ff3);

		// create an AES key from the key data
		SecretKeySpec K = new SecretKeySpec(key, "AES");

		System.out.println("\n==============================================================\n");
		System.out.println(name + "\n");
		System.out.println("FF3-AES" + key.length * 8 + "\n");
		System.out.println("Key is " + Common.byteArrayToHexString(key));
		System.out.println("Radix = " + radix);
		System.out.println("--------------------------------------------------------------\n");
		System.out.println("PT is <" + Common.intArrayToString(plaintext) + ">\n");

		// perform the encryption
		int[] CT = ff3.encrypt(K, tweak, plaintext);

		System.out.println("CT is <" + Common.intArrayToString(CT) + ">");

		// validate the ciphertext
		assertArrayEquals(ciphertext, CT);

		System.out.println("\n--------------------------------------------------------------\n");

		// perform the decryption
		int[] PT = ff3.decrypt(K, tweak, ciphertext);

		System.out.println("PT is <" + Common.intArrayToString(PT) + ">");

		// validate the recovered plaintext
		assertArrayEquals(plaintext, PT);
	}
}
