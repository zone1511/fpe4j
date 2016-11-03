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

/**
 * This package implements the two methods for format-preserving encryption
 * specified in NIST Special Publication 800-38G, Recommendation for Block
 * Cipher Modes of Operation: Methods for Format-Preserving Encryption, as well
 * as the FFX mechanism and A2 and A10 parameter sets for format-preserving
 * encryption described in <a href=
 * "http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.1736&rep=rep1&type=pdf">The
 * FFX Mode of Operation for Format-Preserving Encryption</a>, by Mihir Bellare,
 * Phillip Rogaway, and Terence Spies.
 * 
 * <p>
 * The implementations focus on conformance, rather than on security or
 * performance, and as such they may not be suitable for real-world use with
 * sensitive data.
 * 
 * <p>
 * Both methods FF1 and FF3 are implemented in standalone classes as well as in
 * FFX parameter sets. (Note that the FF2 method was not selected for the March
 * 2016 publication of NIST SP 800-38G.)
 * 
 * <p>
 * Common block cipher modes of encryption, such as AES, take fixed-length
 * blocks of plaintext bytes as input and produce blocks of the same size
 * ciphertext as output. Padding and block chaining modes allow block ciphers to
 * be used to encrypt streams of data of arbitrary length.
 * 
 * <p>
 * In some circumstances, e.g. when working with legacy environments, it is
 * necessary to produce ciphertext in the same format and length, using the same
 * set of symbols as the original plaintext. For example, a payment account
 * number (PAN) consists of up to 19 decimal digits, with the first 6 digits
 * used to identify the payment scheme and issuing bank, and the final digit
 * used as a checksum using the Luhn algorithm. A card payment processor may
 * need to encrypt these PANs in a way that the ciphertext retains some or all
 * of the original attributes of the plaintext, so that systems designed to
 * process the plaintext may also process the ciphertext.
 * 
 * <p>
 * Format-preserving encryption (FPE) methods take strings of symbols as
 * plaintext input, and produce ciphertext output of the same length as the
 * input using the same set of symbols as the input. For the example above, this
 * would allow a card payment processor to encrypt PANs yet retain the same
 * format and structure in the ciphertext as in the plaintext.
 * 
 * <h1>Standalone FF1 and FF3 Usage</h1>
 * 
 * <p>
 * The FF1 and FF3 methods operate on several parameters:
 * <dl>
 * <dd>radix, the range of integer symbols [0..radix-1] used in the input and
 * output
 * <dd>K, an AES encryption key
 * <dd>T, an array of bytes used as an arbitrary "tweak," which is not
 * necessarily secret but which extends and modifies the key
 * <dd>X, an array of integer symbols, each within the range [0..radix-1]
 * </dl>
 * FF3 uses a fixed-length 8 byte tweak, but FF1 accepts an additional
 * parameter:
 * <dl>
 * <dd>maxTlen, the maximum length of T; any length of T in the range
 * [0..maxTlen] is accepted
 * </dl>
 * Both FF1 and FF3 output arrays of integer symbols, with length equal to the
 * input length, and with each symbol in the range [0..radix-1].
 * 
 * <h1>FFX and FFXParameter Usage</h1>
 * 
 * <p>
 * The generic FFX method takes a set of parameters as input and uses those
 * parameters to implement a specific format-preserving encryption algorithm. To
 * use FFX, the caller must implement a complete set of parameters to define a
 * specific algorithm, notably a round function for transformations in the
 * Feistel rounds.
 * 
 * <p>
 * An FFX instance may be instantiated by supplying individual parameters, which
 * follows the FFX specification, or by supplying an FFXParameters object, which
 * provides the additional flexibility necessary to implement FF3 or other FFX
 * variations with custom arithmetic functions.
 * 
 * <p>
 * This implementation includes FFX parameter sets for the FF1 and FF3
 * algorithms, as well as for the A2 and A10 algorithms defined by Bellare,
 * Rogaway, and Spies.
 * 
 * <p>
 * The A2 algorithm operates on arrays of 8 to 128 boolean values, implemented
 * as arrays of integers with a radix of 2. The A10 algorithm operates on arrays
 * of 4 to 36 decimal values, implemented as arrays of integers with a radix of
 * 10. Both A2 and A10 accept tweak arrays of arbitrary length.
 * 
 * <h1>Usage notes for all algorithms</h1>
 * 
 * <p>
 * It is up to the caller to convert between arbitrary data formats, e.g.
 * character-based data, and the arrays of integers that the FF1 and FF3
 * functions use for plaintext and ciphertext input and output. For example, a
 * caller might convert input using the symbols [0123456789BCDFGHJKLMNPQRSTVWXZ]
 * (i.e. the character set for the Natural Area Code) into the integer symbols
 * [0..29], and reverse the conversion using the output.
 * 
 * <p>
 * All these methods of format-preserving encryption operate on uniform arrays
 * of symbols where each symbol is in the same range. They do not preserve data
 * formats where the set of symbols varies depending on the position within the
 * input, such as a license plate number of one decimal digit followed by three
 * upper case letters followed by three decimal digits. If necessary, the caller
 * may transform such input into uniform symbols, then reverse the
 * transformation to restore the original formatting.
 * 
 * <h1>Notes on the Implementation</h1>
 *
 * <p>
 * The standalone FF1 and FF3 implementations follow NIST SP 800-38G as
 * literally as possible, with concessions where needed to represent the
 * concepts in Java. In general, we forego optimizations in favor of a closer
 * match between the code and NIST SP 800-38G. We do, however, make some
 * concessions to readability where a direct interpretation of NIST SP 800-38G
 * would produce verbose code that would be hard to read.
 * 
 * <p>
 * Likewise, the FFX implementation and A2 and A10 parameter sets follow
 * Bellare, Rogaway, and Spies as closely as possible, with concessions where
 * needed in the implementation in Java and for readability, but without
 * optimizations.
 * 
 * <p>
 * To ensure compliance with the original specifications, we validate all inputs
 * as specified, and throw exceptions as appropriate for invalid input.
 * 
 * <h1>Naming</h1>
 *
 * <p>
 * This implementation focuses on conformance with the algorithms defined in the
 * specifications, with naming and structure closely aligned to the definitions
 * in the specifications. As such, variable names in the code defy Java naming
 * conventions in favor of the naming conventions used in the specifications.
 * 
 * <p>
 * So, for example, we use "x" to represent an integer and "X" to represent an
 * array of integers or bytes (i.e. bits), even though this does not follow the
 * Java conventions. We do, however, follow the Java conventions on
 * capitalization of public class members, so e.g. minlen in NIST SP 800-38G is
 * MINLEN, as a public static final member.
 * 
 * <p>
 * Method names, likewise, follow standard Java naming conventions, so "PRF(X)"
 * in NIST SP 800-38G becomes "prf(X)" in the implementation.
 * 
 * <p>
 * The specifications use mathematical symbols for some of their notations,
 * which require alternative naming in Java. In the implementation, these are
 * replaced with descriptive method names. So, for example, the notation
 * "&lfloor;x&rfloor;" becomes "floor(x)" in the implementation.
 * 
 * <p>
 * In some places, the specifications use superscripts and subscripts to specify
 * additional parameters. So, for example, "STR<sup>m</sup><sub>radix</sub>(x)"
 * becomes "str(x,radix,m)" in the implementation.
 * 
 * <h1>Data Types</h1>
 * 
 * <p>
 * NIST SP 800-38G is written in terms of abstract data types, for which we have
 * chosen specific Java types in the implementation.
 * 
 * <p>
 * We use arrays of bytes in place of the bit string type described in NIST SP
 * 800-38G. This implies that bit strings must have a length that is a multiple
 * of 8 bits, but this is consistent with NIST SP 800-38G. (In fact, NIST SP
 * 800-38G may have been clearer if it were written in terms of bytes rather
 * than bits -- see ERRATA.txt.)
 * 
 * <p>
 * We implement the numeral string in NIST SP 800-38G as an array of integers.
 * The range of values for numerals in NIST SP 800-38G is 0..2<sup>radix</sup>,
 * i.e. zero through 2<sup>2</sup>..2<sup>16</sup>, so all the values may be
 * represented using 32-bit two's-compliment Java integers.
 * 
 * <p>
 * Integers in NIST SP 800-38G are implicitly non-negative whole numbers of
 * arbitrary size, so we represent them using the BigInteger class.
 * 
 * <p>
 * As in NIST SP 800-38G, a block is a bit string (i.e. byte string) whose
 * length is the block size of the block cipher (i.e. 128 bits or 16 bytes). We
 * represent these as arrays of multiples of 16 bytes, without any special type.
 * Note that the block size for AES, which is the approved block cipher, is 128
 * bits regardless of the key size.
 * 
 * <p>
 * As described in NIST SP 800-38G, a block string is an array of bits (i.e.
 * bytes) whose length is a multiple of the block size of the block cipher. we
 * represent this as an array of bytes with a length that is a multiple of 16
 * bytes, again without any special type.
 * 
 * <h1>Native Functions</h1>
 * 
 * <p>
 * Some of the functions described in NIST SP 800-38G have native
 * implementations in the Java language and standard libraries. Where
 * appropriate, we have used these native implementations rather than
 * re-implementing the functions.
 * 
 * <p>
 * Instead of implementing new LEN(X) functions for bit strings and numeral
 * strings, we use the length field of the array type. For byte strings the
 * length field is the BYTELEN(X) value, and the value of LEN(X) is X.length *
 * 8. (Again, there is an assumption in NIST SP 800-38G that bit strings are
 * multiples of 8 bits.)
 * 
 * <p>
 * Instead of the mod calculation described in NIST SP 800-38G, we use the
 * Math.floorMod(int) and BigInteger.mod(BigInteger) methods.
 * 
 * <p>
 * The bit string conversion in NIST SP 800-38G is only used with constant
 * inputs, so we sometimes use inline constants in place of the function where
 * this can improve readability.
 * 
 * <p>
 * The PRF(X) function used in FF1 is an implementation of the AES CBC mode
 * without padding, followed by the extraction of the final block of the cipher.
 * We have provided both the direct implementation of the PRF(X) function as
 * Ciphers.prf(X) and an implementation that uses an AES Cipher object in
 * Ciphers.prf2(X).
 * 
 * <h1>JUnit Tests</h1>
 * 
 * <p>
 * The JUnit tests are written to validate inputs and outputs using the sample
 * data for FF1 and FF3 provided by NIST, as well as to provide code coverage
 * and to fully exercise the functions.
 * 
 */
package org.fpe4j;
