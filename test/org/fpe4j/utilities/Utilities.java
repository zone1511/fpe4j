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

/**
 * Utility methods to convert strings to arrays.
 * 
 * @author Kai Johnson
 *
 */
public class Utilities {

	/**
	 * Converts a string representing a hexadecimal value to an array of bytes.
	 * 
	 * @param string
	 *            the string to convert
	 * @return an array of bytes
	 * @throws NullPointerException
	 *             if string is null
	 * @throws IllegalArgumentException
	 *             if the string contains characters that are not valid
	 *             hexadecimal characters, or if the string does not contain an
	 *             even number of characters
	 */
	public static byte[] hexStringToByteArray(String string) {
		// validate string
		if (string == null)
			throw new NullPointerException("string must not be null.");

		int length = string.length();

		if (length % 2 != 0)
			throw new IllegalArgumentException("String must have an even number of characters.");

		// create a new array with one byte for every two characters in the
		// string
		byte bytes[] = new byte[length / 2];

		// for each character in the string
		for (int i = 0; i < length; i++) {
			int digit = Character.digit(string.charAt(i), 16);

			if (digit < 0)
				throw new IllegalArgumentException("Invalid character '" + string.charAt(i) + "' at index " + i + ".");

			// if this is an even character
			if (i % 2 == 0) {
				// use it for the high nibble
				bytes[i / 2] += (byte) (digit << 4);
			} else {
				// use it for the low nibble
				bytes[i / 2] += (byte) digit;
			}
		}
		return bytes;
	}

	/**
	 * Converts a string of integers separated by non-numeric characters to an
	 * array of integers.
	 * 
	 * @param string
	 *            the string to convert
	 * @return an array of integers
	 * @throws NullPointerException
	 *             if string is null
	 */
	public static int[] intStringToIntArray(String string) {
		// validate string
		if (string == null)
			throw new NullPointerException("string must not be null.");

		// split the input string into separate numeric strings
		String strings[] = string.split("[^-0-9]+");
		/*
		 * Note that this will produce empty strings at the start of the array
		 * if there are additional non-numeric characters at the start end of
		 * the input string.
		 */

		// return an empty array if there are no numeric characters in the input
		if (strings.length == 0)
			return new int[0];

		// skip the first string if it's empty
		int s = strings[0].compareTo("") == 0 ? 1 : 0;

		// allocate the output array
		int ints[] = new int[strings.length - s];

		// for each numeric string
		int i = 0;
		for (; s < strings.length; s++) {
			// convert the numeric strings to integers
			ints[i++] = Integer.valueOf(strings[s]).intValue();
			/*
			 * Note that this will throw a RuntimeException if any of the
			 * strings do not contain numeric values.
			 */
		}
		return ints;
	}

	/**
	 * Non-instantiable class.
	 */
	public Utilities() {
		throw new RuntimeException("The Common class cannot be instantiated.");
	}
}
