(* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is TurboPower LockBox
 *
 * The Initial Developer of the Original Code is
 * TurboPower Software
 *
 * Portions created by the Initial Developer are Copyright (C) 1997-2002
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s): Sebastian Zierer
 *
 * ***** END LICENSE BLOCK ***** *)
{*********************************************************}
{*                  LBCONST.PAS 2.08                     *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

unit LbConst;
  {-miscellaneous constants}

interface

const
  { various byte count constants }
  cBytes128 = 16;
  cBytes160 = 20;
  cBytes192 = 24;
  cBytes256 = 32;
  cBytes512 = 64;
  cBytes768 = 96;
  cBytes1024 = 128;

  { defaults }
  cDefIterations  = 20;

{!!.06}
const
  { ASN.1 constants }
  ASN1_TYPE_SEQUENCE        = $10;
  ASN1_TYPE_Integer         = $02;
  ASN1_TAG_NUM_MASK         = $1f;
  ASN1_TYPE_HIGH_TAG_NUMBER = $1f;
  HIGH_BIT_MASK             = $80;
  BIT_MASK_7F               = $7F;



resourcestring

  { version number }
  sLbVersion = '2.08';

  { big integer errors }
  sBIBufferUnderflow   = 'Buffer UnderFlow';
  sBIBufferNotAssigned = 'Buffer not assigned';
  sBINoNumber          = 'No Number';
  sBISubtractErr       = 'Subtraction error';
  sBIZeroDivide        = 'Division by zero';
  sBIQuotientErr       = 'Quotient process error';
  sBIZeroFactor        = 'Factor is zero';
  sBIIterationCount    = 'Iterations must be more than 50';

  { ASN.1 conversion errors }
  sASNKeyTooLarge       = 'ASN key too large';
  sASNKeyBufferOverflow = 'Buffer OverFlow';
  sASNKeyBadModulus     = 'Asymmetric key modulus invalid';
  sASNKeyBadExponent    = 'Asymmetric key exponent invalid';
  sASNKeyBufferTooSmall = 'Buffer too small for key';
  sASNKeyBadKey         = 'Invalid Asymmetric Key';

  { RSA errors }
  sRSAKeyBadKey         = 'Invalid RSA Key';
  sModulusStringTooBig  = 'Modulus string too big';
  sExponentStringTooBig = 'Exponent string too big';
  sRSAKeyPairErr        = 'RSA key pair failure';
  sRSAPublicKeyErr      = 'Invalid RSA public key';
  sRSAPrivateKeyErr     = 'Invalid RSA private key';
  sRSAEncryptErr        = 'RSA encryption failure';
  sRSADecryptErr        = 'RSA decryption failure';
  sRSABlockSize128Err   = 'Invalid block size for key128';
  sRSABlockSize256Err   = 'Invalid block size for key256';
  sRSABlockSize512Err   = 'Invalid block size for key512';
  sRSABlockSize768Err   = 'Invalid block size for key768';
  sRSABlockSize1024Err  = 'Invalid block size for key1024';
  sRSAEncodingErr       = 'RSA encoding error: too much data for block';
  sRSADecodingErrBTS    = 'RSA decoding error: Block too small';
  sRSADecodingErrBTL    = 'RSA decoding error: Block too large';
  sRSADecodingErrIBT    = 'RSA decoding error: Invalid block type';
  sRSADecodingErrIBF    = 'RSA decoding error: Invalid block format';

  { DSA errors }
  sDSAKeyBadKey         = 'Invalid DSA Key';
  sDSAParametersPQGErr  = 'DSA PQG parameter failure';
  sDSAParametersXYErr   = 'DSA XY parameter failure';
  sDSASignatureZeroR    = 'DSA Signature R is zero';
  sDSASignatureZeroS    = 'DSA Signature S is zero';
  sDSASignatureErr      = 'DSA Signature failure';

  { AboutBox errors }
  SNoStart = 'Unable to start web browser. Make sure you have it properly ' +
             'set-up on your system.';

implementation

end.
