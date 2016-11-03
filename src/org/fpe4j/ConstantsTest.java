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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * JUnit test cases for the Constants class.
 * 
 * @author Kai Johnson
 *
 */
public class ConstantsTest {

	/**
	 * Test method for {@link org.fpe4j.Constants#Constants()}.
	 */
	@Test
	public void testConstants() {
		// validate values of MINLEN and MAXLEN
		assertTrue(Constants.MINLEN >= 2);
		assertTrue(Constants.MINLEN <= Constants.MAXLEN);
		assertTrue(Constants.MAXLEN <= Math.pow(2, 32));

		// validate values of MINRADIX and MAXRADIX
		assertTrue(Constants.MINRADIX >= 2);
		assertTrue(Constants.MINRADIX <= Constants.MAXRADIX);
		assertTrue(Constants.MAXRADIX <= Math.pow(2, 16));

		// check constructor
		try {
			new Constants();
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof RuntimeException);
		}
	}

}
