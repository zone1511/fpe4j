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
 * This package implements an experimental method of format-preserving
 * encryption called IFX that operates on strings of non-uniform symbols. The
 * IFX specification is provided in the ifx-spec.pdf file.
 * 
 * <p>
 * The IFX algorithm was developed as a proof of concept for the
 * encoding/decoding process, and the method of splitting non-uniform input
 * strings for Feistel rounds. No assertions are made about the security of the
 * resulting output. Until further cryptanalysis has been performed, this method
 * is NOT RECOMMENDED for use with sensitive data.
 * 
 * <p>
 * The IFX algorithm is implemented as a standalone class, in a separate package
 * from the FFX, FF1 and FF3 methods. Although IFX uses a Feistel network
 * similar to method two of FFX, IFX operates on inputs with different radices
 * for each element, so it is not compatible with the FFX framework.
 * 
 * <h1>Standalone IFX Usage</h1>
 * 
 * <p>
 * The IFX class is instantiated with an array of integers, W, representing the
 * radices of subsequent input and output strings.
 * 
 *
 * <p>
 * The IFX method operates on several parameters:
 * <dl>
 * <dd>K, an AES encryption key
 * <dd>T, an array of bytes used as an arbitrary "tweak," which is not
 * necessarily secret but which extends and modifies the key
 * <dd>X, an array of length(W) integer symbols such that 0 &lt;= X[i] &lt; W[i]
 * for all i in 0..length(W)
 * </dl>
 * IFX permits tweak arrays of arbitrary length, but tweak arrays larger than 16
 * bytes may not provide additional security.
 * 
 * <p>
 * IFX outputs arrays of length(W) integer symbols such that 0 &lt;= Y[i] &lt;
 * W[i] for all i in 0..length(W).
 * 
 * <p>
 * It is up to the caller to convert between arbitrary data formats, e.g.
 * character-based data, and the arrays of integers that the IFX method uses for
 * plaintext and ciphertext input and output. For example, a caller might
 * convert input using the symbols [0123456789BCDFGHJKLMNPQRSTVWXZ] (i.e. the
 * character set for the Natural Area Code) into the integer symbols [0..29],
 * and reverse the conversion using the output.
 * 
 * <h1>Naming</h1>
 *
 * <p>
 * To make comparisons easier, the IFX implementation follows the same naming
 * conventions as the FFX, FF1 and FF3 implementations. See the org.fpe4j
 * package for further information about naming.
 * 
 * <h1>JUnit Tests</h1>
 * 
 * <p>
 * The JUnit tests are written to validate inputs and outputs of each function,
 * as well as to provide code coverage and to fully exercise the functions.
 */
package org.fpe4j.ifx;
