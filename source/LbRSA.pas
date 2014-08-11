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
{*                  LBRSA.PAS 2.08                       *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbRSA;
  {-RSA encryption and signature components, classes, and routines}

interface

uses
{$IFDEF MSWINDOWS}
  Windows,
{$ENDIF}
{$IFDEF POSIX}
  Types,
{$ENDIF}
{$IFDEF UsingCLX}
  Types,
{$ENDIF}
{$IFDEF LINUX}
  Libc,
{$ENDIF}
  Classes,
  SysUtils,
  LbBigInt,
  LbAsym,
  LbCipher,
  LbConst;


const
  { cipher block size constants }                                    {!!.02}
  cRSAMinPadBytes = 11;
  cRSACipherBlockSize : array[TLbAsymKeySize] of Word =
    (cBytes128, cBytes256, cBytes512, cBytes768, cBytes1024);
  cRSAPlainBlockSize : array[TLbAsymKeySize] of Word =
    (cBytes128-cRSAMinPadBytes, cBytes256-cRSAMinPadBytes,
     cBytes512-cRSAMinPadBytes, cBytes768-cRSAMinPadBytes,
     cBytes1024-cRSAMinPadBytes);

type
  { ciphertext block types }                                         {!!.02}
  PRSACipherBlock128 = ^TRSACipherBlock128;
  TRSACipherBlock128 = array[0..cBytes128-1] of Byte;
  PRSACipherBlock256 = ^TRSACipherBlock256;
  TRSACipherBlock256 = array[0..cBytes256-1] of Byte;
  PRSACipherBlock512 = ^TRSACipherBlock512;
  TRSACipherBlock512 = array[0..cBytes512-1] of Byte;
  PRSACipherBlock768 = ^TRSACipherBlock768;
  TRSACipherBlock768 = array[0..cBytes768-1] of Byte;
  PRSACipherBlock1024 = ^TRSACipherBlock1024;
  TRSACipherBlock1024 = array[0..cBytes1024-1] of Byte;

  { plaintext block types }                                          {!!.02}
  PRSAPlainBlock128 = ^TRSAPlainBlock128;
  TRSAPlainBlock128 = array[0..cBytes128-12] of Byte;
  PRSAPlainBlock256 = ^TRSAPlainBlock256;
  TRSAPlainBlock256 = array[0..cBytes256-12] of Byte;
  PRSAPlainBlock512 = ^TRSAPlainBlock512;
  TRSAPlainBlock512 = array[0..cBytes512-12] of Byte;
  PRSAPlainBlock768 = ^TRSAPlainBlock768;
  TRSAPlainBlock768 = array[0..cBytes768-12] of Byte;
  PRSAPlainBlock1024 = ^TRSAPlainBlock1024;
  TRSAPlainBlock1024 = array[0..cBytes1024-12] of Byte;

  { default block type }
  TRSAPlainBlock  = TRSAPlainBlock512;
  TRSACipherBlock = TRSACipherBlock512;

  { signature types }
  TRSASignatureBlock = array[0..cBytes1024-1] of Byte;
  TRSAHashMethod  = (hmMD5, hmSHA1);


type
  TLbRSAGetSignatureEvent = procedure(Sender : TObject;
                                      var Sig : TRSASignatureBlock) of object;
  TLbRSACallback = procedure(var Abort : Boolean) of object;


{ TLbRSAKey }
type
  TLbRSAKey = class(TLbAsymmetricKey)
    protected {private}
      FModulus  : TLbBigInt;
      FExponent : TLbBigInt;
      function ParseASNKey(Input : pByte; Length : Integer) : boolean; override;
      function  CreateASNKey(Input : pByteArray; Length : Integer) : Integer; override;
      function GetModulusAsString : string;
      procedure SetModulusAsString(Value : string);
      function GetExponentAsString : string;
      procedure SetExponentAsString(Value : string);

    public
      constructor Create(aKeySize : TLbAsymKeySize); override;
      destructor Destroy; override;

      procedure Assign(aKey : TLbAsymmetricKey); override;
      procedure Clear;

      property Modulus : TLbBigInt
        read FModulus;
      property ModulusAsString : string
        read GetModulusAsString write SetModulusAsString;
      property Exponent : TLbBigInt
        read FExponent;
      property ExponentAsString : string
        read GetExponentAsString write SetExponentAsString;
      property Passphrase : AnsiString
        read FPassphrase write FPassphrase;
  end;


{ TLbRSA }
type
  TLbRSA = class(TLbAsymmetricCipher)
    protected {private}
      FPrivateKey : TLbRSAKey;
      FPublicKey : TLbRSAKey;
      FPrimeTestIterations : Byte;
      procedure SetKeySize(Value : TLbAsymKeySize); override;
    public {methods}
      constructor Create(AOwner : TComponent); override;
      destructor Destroy; override;
      procedure DecryptFile(const InFile, OutFile : string); override;
      procedure DecryptStream(InStream , OutStream : TStream); override;
      function  DecryptStringA(const InString : AnsiString) : AnsiString; override;
      {$IFDEF UNICODE}
      function  DecryptStringW(const InString : UnicodeString) : UnicodeString; override;
      {$ENDIF}
      procedure EncryptFile(const InFile, OutFile : string); override;
      procedure EncryptStream(InStream, OutStream : TStream); override;
      function  EncryptStringA(const InString : AnsiString) : AnsiString; override;
      {$IFDEF UNICODE}
      function  EncryptStringW(const InString : UnicodeString) : UnicodeString; override;
      {$ENDIF}
      procedure GenerateKeyPair; override;
      function  OutBufSizeNeeded(InBufSize : Cardinal) : Cardinal; override;
      procedure RSACallback(var Abort : Boolean);
    public {properties}
      property PrivateKey : TLbRSAKey
        read FPrivateKey;
      property PublicKey : TLbRSAKey
        read FPublicKey;
    published {properties}
      property PrimeTestIterations : Byte
        read FPrimeTestIterations write FPrimeTestIterations;
      property KeySize;
    published {events}
      property OnProgress;
  end;


{ TLbRSASSA }
type
  TLbRSASSA = class(TLbSignature)
    protected {private}
      FPrivateKey : TLbRSAKey;
      FPublicKey : TLbRSAKey;
      FHashMethod : TRSAHashMethod;
      FPrimeTestIterations : Byte;
      FSignature  : TLbBigInt;
      FOnGetSignature : TLbRSAGetSignatureEvent;
      procedure DoGetSignature;
      procedure EncryptHash(const HashDigest; DigestLen : Cardinal);
      procedure DecryptHash(var HashDigest; DigestLen : Cardinal);
      procedure RSACallback(var Abort : Boolean);
      procedure SetKeySize(Value : TLbAsymKeySize); override;

    public {methods}
      constructor Create(AOwner : TComponent); override;
      destructor Destroy; override;

      procedure GenerateKeyPair; override;
      procedure SignBuffer(const Buf; BufLen : Cardinal); override;
      procedure SignFile(const AFileName : string);  override;
      procedure SignStream(AStream : TStream); override;
      procedure SignStringA(const AStr : AnsiString); override;
      {$IFDEF UNICODE}
      procedure SignStringW(const AStr : UnicodeString); override;
      {$ENDIF}

      function  VerifyBuffer(const Buf; BufLen : Cardinal) : Boolean; override;
      function  VerifyFile(const AFileName : string) : Boolean; override;
      function  VerifyStream(AStream : TStream) : Boolean; override;
      function  VerifyStringA(const AStr : AnsiString) : Boolean; override;
      {$IFDEF UNICODE}
      function  VerifyStringW(const AStr : UnicodeString) : Boolean; override;
      {$ENDIF}

    public {properties}
      property PrivateKey : TLbRSAKey
        read FPrivateKey;
      property PublicKey : TLbRSAKey
        read FPublicKey;
      property Signature : TLbBigInt
        read FSignature;

    published {properties}
      property HashMethod : TRSAHashMethod
        read FHashMethod write FHashMethod;
      property PrimeTestIterations : Byte
        read FPrimeTestIterations write FPrimeTestIterations;
      property KeySize;

    published {events}
      property OnGetSignature : TLbRSAGetSignatureEvent
        read FOnGetSignature write FOnGetSignature;
      property OnProgress;
    end;


{ low level RSA cipher public routines }

{ new public routines }                                              {!!.02}
function EncryptRSAEx(PublicKey : TLbRSAKey; pInBlock, pOutBlock : PByteArray;
           InDataSize : Integer) : Longint;
function DecryptRSAEx(PrivateKey : TLbRSAKey;
           pInBlock, pOutBlock : PByteArray) : Longint;
function  EncryptRSA128(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock128;
            var OutBlock : TRSACipherBlock128) : Longint;
function  DecryptRSA128(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock128;
            var OutBlock : TRSAPlainBlock128) : Longint;
function  EncryptRSA256(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock256;
            var OutBlock : TRSACipherBlock256) : Longint;
function  DecryptRSA256(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock256;
            var OutBlock : TRSAPlainBlock256) : Longint;
function  EncryptRSA512(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock512;
            var OutBlock : TRSACipherBlock512) : Longint;
function  DecryptRSA512(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock512;
            var OutBlock : TRSAPlainBlock512) : Longint;
function  EncryptRSA768(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock768;
            var OutBlock : TRSACipherBlock768) : Longint;
function  DecryptRSA768(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock768;
            var OutBlock : TRSAPlainBlock768) : Longint;
function  EncryptRSA1024(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock1024;
            var OutBlock : TRSACipherBlock1024) : Longint;
function  DecryptRSA1024(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock1024;
            var OutBlock : TRSAPlainBlock1024) : Longint;
{!!.02}

function  EncryptRSA(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock;
            var OutBlock : TRSACipherBlock) : Longint;
function  DecryptRSA(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock;
            var OutBlock : TRSAPlainBlock) : Longint;
procedure RSAEncryptFile(const InFile, OutFile : string;
            Key : TLbRSAKey; Encrypt : Boolean);
procedure RSAEncryptStream(InStream, OutStream : TStream;
            Key : TLbRSAKey; Encrypt : Boolean);
function RSAEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            Key : TLbRSAKey; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function RSAEncryptStringA(const InString : AnsiString;
            Key : TLbRSAKey; Encrypt : Boolean) : AnsiString;
{$IFDEF UNICODE}
function RSAEncryptStringW(const InString : UnicodeString;
            Key : TLbRSAKey; Encrypt : Boolean) : UnicodeString;
{$ENDIF}
procedure GenerateRSAKeysEx(var PrivateKey, PublicKey : TLbRSAKey;
            KeySize : TLbAsymKeySize; PrimeTestIterations : Byte;
            Callback : TLbRSACallback);
procedure GenerateRSAKeys(var PrivateKey, PublicKey : TLbRSAKey);


implementation

uses
  LbUtils, LbString, LbProc;

const
  cDefHashMethod  = hmMD5;

type
  TRSABlockType = (bt00, bt01, bt02);



{ == Local RSA routines ==================================================== }
procedure RSADecodeBlock(biBlock : TLbBigInt);
var
  i : DWord;
  Buf : TRSAPlainBlock1024;
begin
  { verify block format }
  i := biBlock.Size;
  if (i < cRSAMinPadBytes) then
    raise Exception.Create(sRSADecodingErrBTS);
  if (i > cBytes1024) then
    raise Exception.Create(sRSADecodingErrBTL);
  if (biBlock.GetByteValue(i) <> Byte(bt01)) and (biBlock.GetByteValue(i) <> Byte(bt02)) then
    raise Exception.Create(sRSADecodingErrIBT);
  Dec(i);

  { count padding bytes }
  while (biBlock.GetByteValue(i) <> 0) do begin
    Dec(i);
    if (i <= 0) then
    raise Exception.Create(sRSADecodingErrIBF);
  end;

  { strip off padding bytes }
  biBlock.ToBuffer(Buf, i-1);
  biBlock.CopyBuffer(Buf, i-1);
end;
{ -------------------------------------------------------------------------- }
procedure RSAFormatBlock(biBlock : TLbBigInt; BlockType : TRSABlockType);
begin
  if (biBlock.Int.IntBuf.dwLen - biBlock.Int.dwUsed) < 11 then       {!!.02}
    raise Exception.Create(sRSAEncodingErr);                         {!!.02}

  { separate data from padding }
  biBlock.AppendByte($00);

  { append padding }
  while (biBlock.Int.IntBuf.dwLen - biBlock.Int.dwUsed) > 2 do begin {!!.02}
    if (BlockType = bt01) then
      biBlock.AppendByte(Byte($FF))
    else
      biBlock.AppendByte(Byte(Random($FD) + 1));
  end;

  { append tag }
  if (BlockType = bt01) then
    biBlock.AppendByte($01)
  else
    biBlock.AppendByte($02);

  { last byte always 0 }
  biBlock.AppendByte($00);
end;
{ -------------------------------------------------------------------------- }
procedure RSAEncryptBigInt(biBlock : TLbBigInt; Key : TLbRSAKey;
                          BlockType : TRSABlockType; Encrypt : Boolean);
var
  dwSize, dwLen : DWORD;
  tmp1, tmp2 : TLbBigInt;
begin
  tmp1 := TLbBigInt.Create(cLbAsymKeyBytes[Key.KeySize]);
  tmp2 := TLbBigInt.Create(cLbAsymKeyBytes[Key.KeySize]);

  try
    if Encrypt then
      RSAFormatBlock(biBlock, BlockType);
    tmp1.Copy(biBlock);
    dwSize := tmp1.Size;
    biBlock.Clear;
    repeat
      dwLen := Min(dwSize, Key.Modulus.Size);
      tmp2.CopyLen(tmp1, dwLen);
      tmp2.PowerAndMod(Key.Exponent, Key.Modulus);

      biBlock.Append(tmp2);
      tmp1.Shr_(dwLen * 8);
      dwSize := dwSize - dwLen;
    until (dwSize <= 0);

    if Encrypt then                                                  {!!.02}
      { replace leading zeros that were trimmed in the math }        {!!.02}
      while (biBlock.Size < cLbAsymKeyBytes[Key.KeySize]) do         {!!.02}
        biBlock.AppendByte($00)                                      {!!.02}
    else                                                             {!!.02}
      RSADecodeBlock(biBlock);

  finally
    tmp1.Free;
    tmp2.Free;
  end;
end;


{ == Public RSA routines =================================================== }
procedure GenerateRSAKeys(var PrivateKey, PublicKey : TLbRSAKey);
  { create RSA public/private key pair with default settings }
begin
  GenerateRSAKeysEx(PrivateKey, PublicKey, cLbDefAsymKeySize, cDefIterations, nil);
end;
{ -------------------------------------------------------------------------- }
procedure GenerateRSAKeysEx(var PrivateKey, PublicKey : TLbRSAKey;
                            KeySize : TLbAsymKeySize;
                            PrimeTestIterations : Byte;
                            Callback : TLbRSACallback);
  { create RSA key pair speciying size and prime test iterations and }
  { callback function }
var
  q : TLbBigInt;
  p : TLbBigInt;
  p1q1 : TLbBigInt;
  d : TLbBigInt;
  e : TLbBigInt;
  n : TLbBigInt;
  Abort : Boolean;
begin
  PrivateKey := TLbRSAKey.Create(KeySize);
  PublicKey := TLbRSAKey.Create(KeySize);

  { create temp variables }
  p1q1 := TLbBigInt.Create(cLbAsymKeyBytes[KeySize]);
  d := TLbBigInt.Create(cLbAsymKeyBytes[KeySize]);
  e := TLbBigInt.Create(cLbAsymKeyBytes[KeySize]);
  n := TLbBigInt.Create(cLbAsymKeyBytes[KeySize]);
  p := TLbBigInt.Create(cLbAsymKeyBytes[KeySize] div 2);
  q := TLbBigInt.Create(cLbAsymKeyBytes[KeySize] div 2);

  try
    Abort := False;
    repeat
      { p , q = random primes }
      repeat
        p.RandomPrime(PrimeTestIterations);
        { check for abort }
        if Assigned(Callback) then
          Callback(Abort);
        if Abort then
          Exit;
        q.RandomPrime(PrimeTestIterations);
        { check for abort }
        if Assigned(Callback) then
          Callback(Abort);
        if Abort then
          Exit;
      until (p.Compare(q) <> 0);

      { n = pq }
      n.Copy(p);
      n.Multiply(q);

      { p1q1 = (p-1)(q-1) }
      p.SubtractByte($01);
      q.SubtractByte($01);
      p1q1.Copy(p);
      p1q1.Multiply(q);

      { e = randomly chosen simple prime > 3 }
      e.RandomSimplePrime;


      { d = inverse(e) mod (p-1)(q-1) }
      d.Copy(e);
    until d.ModInv(p1q1);

    { assign n and d to private key }
    PrivateKey.Modulus.Copy(n);
    PrivateKey.Exponent.Copy(d);

    { assign n and e to public key }
    PublicKey.Modulus.Copy(n);
    PublicKey.Exponent.Copy(e);

  finally
    p1q1.Free;
    d.Free;
    e.Free;
    n.Free;
    p.Free;
    q.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function EncryptRSAEx(PublicKey : TLbRSAKey;
                      pInBlock, pOutBlock : PByteArray;
                      InDataSize : Integer) : Longint;
  { IMPORTANT: verify block sizes before calling this routine }
var
  biBlock : TLbBigInt;
  OutSize : DWord;
begin
  OutSize := cRSACipherBlockSize[PublicKey.KeySize];
  biBlock := TLbBigInt.Create(OutSize);
  try
    biBlock.CopyBuffer(pInBlock^, InDataSize);
    RSAEncryptBigInt(biBlock, PublicKey, bt02, True);
    if Integer(OutSize) < biBlock.Size then                          {!!.05}
      raise Exception.Create('OutBlock size too small');

    biBlock.ToBuffer(pOutBlock^, biBlock.Size);
  finally
    Result := biBlock.Size;
    biBlock.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function DecryptRSAEx(PrivateKey : TLbRSAKey;
                      pInBlock, pOutBlock : PByteArray) : Longint;
  { IMPORTANT: verify block sizes before calling this routine }
var
  biBlock : TLbBigInt;
  InSize, OutSize : DWord;
begin
  InSize := cRSACipherBlockSize[PrivateKey.KeySize];
  OutSize := cRSAPlainBlockSize[PrivateKey.KeySize];
  biBlock := TLbBigInt.Create(InSize);
  try
    biBlock.CopyBuffer(pInBlock^, InSize);
    RSAEncryptBigInt(biBlock, PrivateKey, bt02, False);
    if Integer(OutSize) < biBlock.Size then                          {!!.05}
      raise Exception.Create('OutBlock size too small');

    biBlock.ToBuffer(pOutBlock^, biBlock.Size);
  finally
    Result := biBlock.Size;
    biBlock.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  EncryptRSA128(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock128;
            var OutBlock : TRSACipherBlock128) : Longint;
  { encrypt plaintext block with 128-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks128) then
    raise Exception.Create(sRSABlockSize128Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  DecryptRSA128(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock128;
            var OutBlock : TRSAPlainBlock128) : Longint;
  { decrypt ciphertext block with 128-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks128) then
    raise Exception.Create(sRSABlockSize128Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  EncryptRSA256(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock256;
            var OutBlock : TRSACipherBlock256) : Longint;
  { encrypt plaintext block with 256-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks256) then
    raise Exception.Create(sRSABlockSize256Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  DecryptRSA256(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock256;
            var OutBlock : TRSAPlainBlock256) : Longint;
  { decrypt ciphertext block with 256-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks256) then
    raise Exception.Create(sRSABlockSize256Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  EncryptRSA512(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock512;
            var OutBlock : TRSACipherBlock512) : Longint;
  { encrypt plaintext block with 512-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks512) then
    raise Exception.Create(sRSABlockSize512Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  DecryptRSA512(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock512;
            var OutBlock : TRSAPlainBlock512) : Longint;
  { decrypt ciphertext block with 512-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks512) then
    raise Exception.Create(sRSABlockSize512Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  EncryptRSA768(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock768;
            var OutBlock : TRSACipherBlock768) : Longint;
  { encrypt plaintext block with 768-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks768) then
    raise Exception.Create(sRSABlockSize768Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  DecryptRSA768(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock768;
            var OutBlock : TRSAPlainBlock768) : Longint;
  { decrypt ciphertext block with 768-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks768) then
    raise Exception.Create(sRSABlockSize768Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  EncryptRSA1024(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock1024;
            var OutBlock : TRSACipherBlock1024) : Longint;
  { encrypt plaintext block with 1024-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks1024) then
    raise Exception.Create(sRSABlockSize1024Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;
{ -------------------------------------------------------------------------- }
{!!.02}
function  DecryptRSA1024(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock1024;
            var OutBlock : TRSAPlainBlock1024) : Longint;
  { decrypt ciphertext block with 1024-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks1024) then
    raise Exception.Create(sRSABlockSize1024Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;
{ -------------------------------------------------------------------------- }
function EncryptRSA(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock;
           var OutBlock : TRSACipherBlock) : Longint;
  { encrypt plaintext block with 512-bit RSA public key }
begin
  Result := EncryptRSA512(PublicKey, InBlock, OutBlock);             {!!.02}
end;
{ -------------------------------------------------------------------------- }
function DecryptRSA(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock;
           var OutBlock : TRSAPlainBlock) : Longint;
  { decrypt ciphertext block with 512-bit RSA private key }
begin
  Result := DecryptRSA512(PrivateKey, InBlock, OutBlock);            {!!.02}
end;
{ -------------------------------------------------------------------------- }
procedure RSAEncryptFile(const InFile, OutFile : string;
            Key : TLbRSAKey; Encrypt : Boolean);
  { encrypt/decrypt file data with RSA key }
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      RSAEncryptStream(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure RSAEncryptStream(InStream, OutStream : TStream;
            Key : TLbRSAKey; Encrypt : Boolean);
  { encrypt/decrypt stream data with RSA key }
var
  InBlkCount  : Integer;
  InBlkSize, OutBlkSize : Integer;
  PlainBlockSize, CipherBlockSize : Integer;
  i : Integer;
  pInBlk, pOutBlk       : Pointer;
  PlainBlock, CipherBlock : TRSACipherBlock1024;
begin
  PlainBlockSize := cRSAPlainBlockSize[Key.KeySize];
  CipherBlockSize := cRSACipherBlockSize[Key.KeySize];
  if Encrypt then begin
    pInBlk := @PlainBlock;
    pOutBlk := @CipherBlock;
    InBlkSize := PlainBlockSize;
    OutBlkSize := CipherBlockSize;
  end else begin
    pInBlk := @CipherBlock;
    pOutBlk := @PlainBlock;
    InBlkSize := CipherBlockSize;
    OutBlkSize := PlainBlockSize;
  end;

  InBlkCount := InStream.Size div InBlkSize;
  if (InStream.Size mod InBlkSize) > 0 then
    Inc(InBlkCount);

  { process all except the last block }
  for i := 1 to (InBlkCount - 1) do begin
    InStream.Read(pInBlk^, InBlkSize);
    if Encrypt then
      EncryptRSAEx(Key, pInBlk, pOutBlk, InBlkSize)
    else
      DecryptRSAEx(Key, pInBlk, pOutBlk);
    OutStream.Write(pOutBlk^, OutBlkSize);
  end;

  { process the last block }
  i := InStream.Read(pInBlk^, InBlkSize);
  if Encrypt then
    i := EncryptRSAEx(Key, pInBlk, pOutBlk, i)
  else
    i := DecryptRSAEx(Key, pInBlk, pOutBlk);
  OutStream.Write(pOutBlk^, i);
end;
{ -------------------------------------------------------------------------- }
function RSAEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            Key : TLbRSAKey; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
  { encrypt/decrypt string data with RSA key }
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := RSAEncryptStringW(InString, Key, Encrypt);
  {$ELSE}
  Result := RSAEncryptStringA(InString, Key, Encrypt);
  {$ENDIF}
end;

function RSAEncryptStringA(const InString : AnsiString;
            Key : TLbRSAKey; Encrypt : Boolean) : AnsiString;
var
  InStream  : TMemoryStream;
  OutStream : TMemoryStream;
  WorkStream : TMemoryStream;
begin
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  WorkStream := TMemoryStream.Create;
  InStream.Write(InString[1], Length(InString) * SizeOf(AnsiChar));
  InStream.Position := 0;

  if Encrypt then begin
    RSAEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    RSAEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

{$IFDEF UNICODE}
function RSAEncryptStringW(const InString : UnicodeString;
            Key : TLbRSAKey; Encrypt : Boolean) : UnicodeString;
var
  InStream  : TMemoryStream;
  OutStream : TMemoryStream;
  WorkStream : TMemoryStream;
begin
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  WorkStream := TMemoryStream.Create;
  InStream.Write(InString[1], Length(InString) * SizeOf(WideChar));
  InStream.Position := 0;

  if Encrypt then begin
    RSAEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    RSAEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(Char));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}


{ == TLbRSAKey ============================================================= }
constructor TLbRSAKey.Create(aKeySize : TLbAsymKeySize);
  { initialization }
begin
  inherited Create(aKeySize);

  FModulus := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  FExponent := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
end;
{ -------------------------------------------------------------------------- }
destructor TLbRSAKey.Destroy;
  { finalization }
begin
  FModulus.Free;
  FExponent.Free;

  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSAKey.Assign(aKey : TLbAsymmetricKey);
  { copy exponent and modulus values from another key }
begin
  inherited Assign(aKey);

  if (aKey is TLbRSAKey) then begin
    FModulus.Copy(TLbRSAKey(aKey).Modulus);
    FExponent.Copy(TLbRSAKey(aKey).Exponent);
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSAKey.Clear;
  { reset exponent and modulus }
begin
  FModulus.Clear;
  FExponent.Clear;
end;
{ -------------------------------------------------------------------------- }
function TLbRSAKey.GetModulusAsString : string;
  { return "big to little" hex string representation of modulus }
begin
  Result := FModulus.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSAKey.SetModulusAsString(Value : string);
  { set modulus to value represented by "big to little" hex string }
var
  Buf : array[Byte] of Byte;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, cLbAsymKeyBytes[FKeySize]);
  FModulus.CopyBuffer(Buf, cLbAsymKeyBytes[FKeySize]);
  FModulus.Trim;
end;
{ -------------------------------------------------------------------------- }
function TLbRSAKey.GetExponentAsString : string;
  { return "big to little" hex string representation of exponent }
begin
  Result := FExponent.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSAKey.SetExponentAsString(Value : string);
  { set exponent to value represented by "big to little" hex string }
var
  Buf : array[Byte] of Byte;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, cLbAsymKeyBytes[FKeySize]);
  FExponent.CopyBuffer(Buf, cLbAsymKeyBytes[FKeySize]);
  FExponent.Trim;
end;
{------------------------------------------------------------------------------}
function TLbRSAKey.CreateASNKey(Input : pByteArray; Length : Integer) : Integer;
const
  TAG30 = $30;
var
  ExpSize : Integer;
  ModSize : Integer;
  Total : Integer;
  pInput : PByteArray;
  Max : Integer;
begin
  pInput := Input;
  Max := Length;
  ModSize := EncodeASN1(FModulus, pInput, Max);
  ExpSize := EncodeASN1(FExponent, pInput, Max);
  Total := ExpSize + ModSize;
  CreateASN1(Input^, Total, TAG30);
  Result := Total;
end;
{------------------------------------------------------------------------------}
function TLbRSAKey.ParseASNKey(Input : PByte; Length : Integer) : Boolean;
var
  Tag : Integer;
  Max : Integer;
  pInput : PByte;
begin
  Max := Length;
  pInput := Input;

  { check for sequence }
  Tag := GetASN1StructNum(pInput, Max);
  GetASN1StructLen(pInput, Max);

  if (Tag <> ASN1_TYPE_SEQUENCE) then
    raise Exception.Create(sRSAKeyBadKey);

  ParseASN1(pInput, Max, FModulus);
  ParseASN1(pInput, Max, FExponent);

  Result := (Max = 0);
end;



{ == TLbRSA ================================================================ }
constructor TLbRSA.Create(AOwner : TComponent);
  { initialize }
begin
  inherited Create(AOwner);

  FPrivateKey := TLbRSAKey.Create(FKeySize);
  FPublicKey  := TLbRSAKey.Create(FKeySize);
  FPrimeTestIterations := cDefIterations;
end;
{ -------------------------------------------------------------------------- }
destructor TLbRSA.Destroy;
  { finalize }
begin
  FPrivateKey.Free;
  FPublicKey.Free;

  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSA.DecryptFile(const InFile, OutFile : string);
  { decrypt file data with RSA private key }
begin
  RSAEncryptFile(InFile, OutFile, FPrivateKey, False);
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSA.DecryptStream(InStream , OutStream : TStream);
  { decrypt stream data with RSA private key }
begin
  RSAEncryptStream(InStream, OutStream, FPrivateKey, False);
end;
{ -------------------------------------------------------------------------- }
function TLbRSA.DecryptStringA(const InString : AnsiString) : AnsiString;
  { decrypt string data with RSA private key }
begin
  Result := RSAEncryptStringA(InString, FPrivateKey, False);
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
function TLbRSA.DecryptStringW(const InString : UnicodeString) : UnicodeString;
  { decrypt string data with RSA private key }
begin
  Result := RSAEncryptStringW(InString, FPrivateKey, False);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure TLbRSA.EncryptFile(const InFile, OutFile : string);
  { encrypt file data with RSA public key }
begin
  RSAEncryptFile(InFile, OutFile, FPublicKey, True);
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSA.EncryptStream(InStream, OutStream : TStream);
  { encrypt stream data with RSA public key }
begin
  RSAEncryptStream(InStream, OutStream, FPublicKey, True);
end;
{ -------------------------------------------------------------------------- }
function TLbRSA.EncryptStringA(const InString : AnsiString) : AnsiString;
  { encrypt string data with RSA public key }
begin
  Result := RSAEncryptStringA(InString, FPublicKey, True);
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
function TLbRSA.EncryptStringW(const InString : UnicodeString) : UnicodeString;
  { encrypt string data with RSA public key }
begin
  Result := RSAEncryptStringW(InString, FPublicKey, True);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure TLbRSA.GenerateKeyPair;
  { generate RSA public/private key pair }
begin
  if Assigned(FPrivateKey) then
    FPrivateKey.Free;
  if Assigned(FPublicKey) then
    FPublicKey.Free;
  try
    GenerateRSAKeysEx(FPrivateKey, FPublicKey, FKeySize,
      FPrimeTestIterations, RSACallback);
  except
    raise Exception.Create(sRSAKeyPairErr);
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbRSA.OutBufSizeNeeded(InBufSize : Cardinal) : Cardinal;
  { return size of ciphertext buffer required to encrypt plaintext InBuf }
var
  BlkCount : Cardinal;
begin
  BlkCount := InBufSize div cRSAPlainBlockSize[FKeySize];            {!!.02}
  if (InBufSize mod cRSAPlainBlockSize[FKeySize]) > 0 then           {!!.02}
    Inc(BlkCount);
  Result := BlkCount * cRSACipherBlockSize[FKeySize];                {!!.02}
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSA.RSACallback(var Abort : Boolean);
  { pass callback on via OnProgress event }
begin
  Abort := False;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Abort);
end;
{ -------------------------------------------------------------------------- }
{!!.02}
procedure TLbRSA.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
  FPublicKey.KeySize := FKeySize;
  FPrivateKey.KeySize := FKeySize;
end;



{ == TLbRSASSA ============================================================= }
constructor TLbRSASSA.Create(AOwner : TComponent);
  { initialize }
begin
  inherited Create(AOwner);

  FPrivateKey := TLbRSAKey.Create(FKeySize);
  FPublicKey  := TLbRSAKey.Create(FKeySize);
  FSignature  := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  FHashMethod := cDefHashMethod;
  FPrimeTestIterations := cDefIterations;
end;
{ -------------------------------------------------------------------------- }
destructor TLbRSASSA.Destroy;
  { finalize }
begin
  FPrivateKey.Free;
  FPublicKey.Free;
  FSignature.Free;

  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.DoGetSignature;
  { fire OnGetSignature event to obtain RSA signature }
var
  SigBlock : TRSASignatureBlock;
begin
  if Assigned(FOnGetSignature) then begin
    FillChar(SigBlock, SizeOf(SigBlock), #0);
    FOnGetSignature(Self, SigBlock);
    FSignature.CopyBuffer(SigBlock, cLbAsymKeyBytes[FKeySize]);      {!!.02}
    FSignature.Trim;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.GenerateKeyPair;
  { generate RSA public/private key pair }
begin
  if Assigned(FPrivateKey) then
    FPrivateKey.Free;
  if Assigned(FPublicKey) then
    FPublicKey.Free;
  GenerateRSAKeysEx(FPrivateKey, FPublicKey, FKeySize, FPrimeTestIterations,
                    RSACallback);
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.EncryptHash(const HashDigest; DigestLen : Cardinal);
  { encrypt message digest into signature }
begin
  if (FPrivateKey.Modulus.Size = 0) then                             {!!.02}
    raise Exception.Create(sRSAPrivateKeyErr);

  FSignature.CopyBuffer(HashDigest, DigestLen);
  RSAEncryptBigInt(FSignature, FPrivateKey, bt01, True);             {!!.02}
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.DecryptHash(var HashDigest; DigestLen : Cardinal);
  { decrypt signature into message digest }
var
  biBlock : TLbBigInt;
begin
  if (FPublicKey.Modulus.Size = 0) then                              {!!.02}
    raise Exception.Create(sRSAPublicKeyErr);

  biBlock := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  try
    DoGetSignature;
    biBlock.Copy(FSignature);
    RSAEncryptBigInt(biBlock, FPublicKey, bt01, False);              {!!.02}
    FillChar(HashDigest, DigestLen, #0);
    if biBlock.Size < Integer(DigestLen) then                        {!!.05}
      biBlock.ToBuffer(HashDigest, biBlock.Size)
    else
      biBlock.ToBuffer(HashDigest, DigestLen);
  except
    { just swallow the error, signature comparison will fail benignly }
  end;
  biBlock.Free;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.SignBuffer(const Buf; BufLen : Cardinal);
  { generate RSA signature of buffer data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        HashMD5(MD5Digest, Buf, BufLen);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        HashSHA1(SHA1Digest, Buf, BufLen);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.SignFile(const AFileName : string);
  { generate RSA signature of file data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        FileHashMD5(MD5Digest, AFileName);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        FileHashSHA1(SHA1Digest, AFileName);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.SignStream(AStream : TStream);
  { generate RSA signature of stream data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        StreamHashMD5(MD5Digest, AStream);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        StreamHashSHA1(SHA1Digest, AStream);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.SignStringA(const AStr : AnsiString);
  { generate RSA signature of string data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        StringHashMD5A(MD5Digest, AStr);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        StringHashSHA1A(SHA1Digest, AStr);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure TLbRSASSA.SignStringW(const AStr : UnicodeString);
  { generate RSA signature of string data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        StringHashMD5W(MD5Digest, AStr);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        StringHashSHA1W(SHA1Digest, AStr);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
function TLbRSASSA.VerifyBuffer(const Buf; BufLen : Cardinal) : Boolean;
  { verify RSA signature agrees with buffer data }
var
  MD5Digest1  : TMD5Digest;
  MD5Digest2  : TMD5Digest;
  SHA1Digest1 : TSHA1Digest;
  SHA1Digest2 : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5 :
      begin
        DecryptHash(MD5Digest1, SizeOf(TMD5Digest));
        HashMD5(MD5Digest2, Buf, BufLen);
        Result := CompareBuffers(MD5Digest1, MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        HashSHA1(SHA1Digest2, Buf, BufLen);
        Result := CompareBuffers(SHA1Digest1, SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbRSASSA.VerifyFile(const AFileName : string) : Boolean;
  { verify RSA signature agrees with file data }
var
  MD5Digest1  : TMD5Digest;
  MD5Digest2  : TMD5Digest;
  SHA1Digest1 : TSHA1Digest;
  SHA1Digest2 : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5 :
      begin
        DecryptHash(MD5Digest1, SizeOf(TMD5Digest));
        FileHashMD5(MD5Digest2, AFileName);
        Result := CompareBuffers(MD5Digest1, MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        FileHashSHA1(SHA1Digest2, AFileName);
        Result := CompareBuffers(SHA1Digest1, SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbRSASSA.VerifyStream(AStream : TStream) : Boolean;
  { verify RSA signature agrees with stream data }
var
  MD5Digest1  : TMD5Digest;
  MD5Digest2  : TMD5Digest;
  SHA1Digest1 : TSHA1Digest;
  SHA1Digest2 : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5 :
      begin
        DecryptHash(MD5Digest1, SizeOf(TMD5Digest));
        StreamHashMD5(MD5Digest2, AStream);
        Result := CompareBuffers(MD5Digest1, MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        StreamHashSHA1(SHA1Digest2, AStream);
        Result := CompareBuffers(SHA1Digest1, SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbRSASSA.VerifyStringA(const AStr : AnsiString) : Boolean;
  { verify RSA signature agrees with string data }
var
  MD5Digest1  : TMD5Digest;
  MD5Digest2  : TMD5Digest;
  SHA1Digest1 : TSHA1Digest;
  SHA1Digest2 : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5 :
      begin
        DecryptHash(MD5Digest1, SizeOf(TMD5Digest));
        StringHashMD5A(MD5Digest2, AStr);
        Result := CompareBuffers(MD5Digest1, MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        StringHashSHA1A(SHA1Digest2, AStr);
        Result := CompareBuffers(SHA1Digest1, SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
function TLbRSASSA.VerifyStringW(const AStr : UnicodeString) : Boolean;
  { verify RSA signature agrees with string data }
var
  MD5Digest1  : TMD5Digest;
  MD5Digest2  : TMD5Digest;
  SHA1Digest1 : TSHA1Digest;
  SHA1Digest2 : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5 :
      begin
        DecryptHash(MD5Digest1, SizeOf(TMD5Digest));
        StringHashMD5W(MD5Digest2, AStr);
        Result := CompareBuffers(MD5Digest1, MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        StringHashSHA1W(SHA1Digest2, AStr);
        Result := CompareBuffers(SHA1Digest1, SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure TLbRSASSA.RSACallback(var Abort : Boolean);
  { pass callback on via OnProgress event }
begin
  Abort := False;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Abort);
end;
{ -------------------------------------------------------------------------- }
{!!.02}
procedure TLbRSASSA.SetKeySize(Value : TLbAsymKeySize);
begin
  if (Ord(Value) < Ord(aks256)) then begin
    if (csDesigning in ComponentState) then
      FKeySize := aks256
    else
      raise Exception.Create('Invalid key size for RSASSA');
  end else
    FKeySize := Value;
  FPublicKey.KeySize := FKeySize;
  FPrivateKey.KeySize := FKeySize;
  FSignature.Free;
  FSignature := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
end;


end.

