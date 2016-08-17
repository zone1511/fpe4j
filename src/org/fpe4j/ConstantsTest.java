/**
 * 
 */
package org.fpe4j;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * JUnit test cases for the Constants class
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
