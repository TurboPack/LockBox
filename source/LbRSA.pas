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
 * Contributor(s): Roman Kassebaum
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
  System.Types, System.Classes, System.SysUtils, LbBigInt, LbAsym, LbCipher, LbConst;

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
  TRSABlockType = (bt00, bt01, bt02);

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

  TLbRSAGetSignatureEvent = procedure(Sender : TObject; var Sig : TRSASignatureBlock) of object;
  TLbRSACallback = procedure(var Abort : Boolean) of object;

  TLbRSAKey = class(TLbAsymmetricKey)
  strict private
    FModulus  : TLbBigInt;
    FExponent : TLbBigInt;
    function GetModulusAsString : string;
    procedure SetModulusAsString(Value : string);
    function GetExponentAsString : string;
    procedure SetExponentAsString(Value : string);

  strict protected
    function CreateASNKey(Input : pByteArray; Length : Integer): Integer; override;
    function ParseASNKey(Input : pByte; Length : Integer): boolean; override;
  public
    constructor Create(aKeySize : TLbAsymKeySize); override;
    destructor Destroy; override;

    procedure Assign(aKey : TLbAsymmetricKey); override;
    procedure Clear;

    property Modulus : TLbBigInt read FModulus;
    property ModulusAsString : string read GetModulusAsString write SetModulusAsString;
    property Exponent : TLbBigInt read FExponent;
    property ExponentAsString : string read GetExponentAsString write SetExponentAsString;
  end;

  TLbRSA = class(TLbAsymmetricCipher)
  strict private
    FPrivateKey : TLbRSAKey;
    FPublicKey : TLbRSAKey;
    FPrimeTestIterations : Byte;
  strict protected
    procedure SetKeySize(Value : TLbAsymKeySize); override;
  public
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
    procedure DecryptFile(const InFile, OutFile : string); override;
    procedure DecryptStream(InStream , OutStream : TStream); override;
    function  DecryptString(const InString : string) : string; override;
    procedure EncryptFile(const InFile, OutFile : string); override;
    procedure EncryptStream(InStream, OutStream : TStream); override;
    function  EncryptString(const InString : string) : string; override;
    procedure GenerateKeyPair; override;
    function  OutBufSizeNeeded(InBufSize : Cardinal) : Cardinal; override;
    procedure RSACallback(var Abort : Boolean);
    property PrivateKey : TLbRSAKey read FPrivateKey;
    property PublicKey : TLbRSAKey read FPublicKey;
  published
    property PrimeTestIterations : Byte read FPrimeTestIterations write FPrimeTestIterations;
    property KeySize;
    property OnProgress;
  end;

  TLbRSASSA = class(TLbSignature)
  strict private
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
  strict protected
    procedure SetKeySize(Value : TLbAsymKeySize); override;
  public
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;

    procedure GenerateKeyPair; override;
    procedure SignBuffer(const Buf; BufLen : Cardinal); override;
    procedure SignFile(const AFileName : string);  override;
    procedure SignStream(AStream : TStream); override;
    procedure SignString(const AStr : string); override;

    function  VerifyBuffer(const Buf; BufLen : Cardinal) : Boolean; override;
    function  VerifyFile(const AFileName : string) : Boolean; override;
    function  VerifyStream(AStream : TStream) : Boolean; override;
    function  VerifyString(const AStr : string) : Boolean; override;
  public
    property PrivateKey : TLbRSAKey read FPrivateKey;
    property PublicKey : TLbRSAKey read FPublicKey;
    property Signature : TLbBigInt read FSignature;

  published
    property HashMethod : TRSAHashMethod read FHashMethod write FHashMethod;
    property PrimeTestIterations : Byte read FPrimeTestIterations write FPrimeTestIterations;
    property KeySize;
    property OnGetSignature : TLbRSAGetSignatureEvent read FOnGetSignature write FOnGetSignature;
    property OnProgress;
  end;

  TRSA = record
  private
    class procedure RSADecodeBlock(biBlock : TLbBigInt); static;
    class procedure RSAEncryptBigInt(biBlock : TLbBigInt; Key : TLbRSAKey; BlockType : TRSABlockType; Encrypt : Boolean); static;
    class procedure RSAFormatBlock(biBlock : TLbBigInt; BlockType : TRSABlockType); static;
  public
    class function DecryptRSA(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock; var OutBlock : TRSAPlainBlock): Longint; static;
    class function DecryptRSA1024(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock1024; var OutBlock : TRSAPlainBlock1024): Longint; static;
    class function DecryptRSA128(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock128; var OutBlock : TRSAPlainBlock128): Longint; static;
    class function DecryptRSA256(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock256; var OutBlock : TRSAPlainBlock256): Longint; static;
    class function DecryptRSA512(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock512; var OutBlock : TRSAPlainBlock512): Longint; static;
    class function DecryptRSA768(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock768; var OutBlock : TRSAPlainBlock768): Longint; static;
    class function DecryptRSAEx(PrivateKey : TLbRSAKey; pInBlock, pOutBlock : PByteArray): Longint; static;
    class function EncryptRSA(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock; var OutBlock : TRSACipherBlock): Longint; static;
    class function EncryptRSA1024(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock1024; var OutBlock : TRSACipherBlock1024): Longint; static;
    class function EncryptRSA128(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock128; var OutBlock : TRSACipherBlock128): Longint; static;
    class function EncryptRSA256(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock256; var OutBlock : TRSACipherBlock256): Longint; static;
    class function EncryptRSA512(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock512; var OutBlock : TRSACipherBlock512): Longint; static;
    class function EncryptRSA768(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock768; var OutBlock : TRSACipherBlock768): Longint; static;
    class function EncryptRSAEx(PublicKey : TLbRSAKey; pInBlock, pOutBlock : PByteArray; InDataSize : Integer): Longint; static;
    class procedure GenerateRSAKeys(var PrivateKey, PublicKey : TLbRSAKey); static;
    class procedure GenerateRSAKeysEx(var PrivateKey, PublicKey : TLbRSAKey; KeySize : TLbAsymKeySize; PrimeTestIterations : Byte; Callback : TLbRSACallback); static;
    class procedure RSAEncryptFile(const InFile, OutFile : string; Key : TLbRSAKey; Encrypt : Boolean); static;
    class procedure RSAEncryptStream(InStream, OutStream : TStream; Key : TLbRSAKey; Encrypt : Boolean); static;
    class function RSAEncryptBytes(const InBytes: TBytes; Key: TLbRSAKey; Encrypt: Boolean): TBytes; static;
  end;

implementation

uses
  System.Math, LbUtils, LbBytes, LbProc;

{ TLbRSAKey }

constructor TLbRSAKey.Create(aKeySize : TLbAsymKeySize);
  { initialization }
begin
  inherited Create(aKeySize);

  FModulus := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  FExponent := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
end;

destructor TLbRSAKey.Destroy;
  { finalization }
begin
  FModulus.Free;
  FExponent.Free;

  inherited Destroy;
end;

procedure TLbRSAKey.Assign(aKey : TLbAsymmetricKey);
  { copy exponent and modulus values from another key }
begin
  inherited Assign(aKey);

  if (aKey is TLbRSAKey) then begin
    FModulus.Copy(TLbRSAKey(aKey).Modulus);
    FExponent.Copy(TLbRSAKey(aKey).Exponent);
  end;
end;

procedure TLbRSAKey.Clear;
  { reset exponent and modulus }
begin
  FModulus.Clear;
  FExponent.Clear;
end;

function TLbRSAKey.GetModulusAsString : string;
  { return "big to little" hex string representation of modulus }
begin
  Result := FModulus.IntStr;
end;

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

function TLbRSAKey.GetExponentAsString : string;
  { return "big to little" hex string representation of exponent }
begin
  Result := FExponent.IntStr;
end;

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

function TLbRSAKey.CreateASNKey(Input : pByteArray; Length : Integer): Integer;
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

function TLbRSAKey.ParseASNKey(Input : pByte; Length : Integer): boolean;
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

{ TLbRSA }

constructor TLbRSA.Create(AOwner : TComponent);
  { initialize }
begin
  inherited Create(AOwner);

  FPrivateKey := TLbRSAKey.Create(FKeySize);
  FPublicKey  := TLbRSAKey.Create(FKeySize);
  FPrimeTestIterations := cDefIterations;
end;

destructor TLbRSA.Destroy;
  { finalize }
begin
  FPrivateKey.Free;
  FPublicKey.Free;

  inherited Destroy;
end;

procedure TLbRSA.DecryptFile(const InFile, OutFile : string);
  { decrypt file data with RSA private key }
begin
  TRSA.RSAEncryptFile(InFile, OutFile, FPrivateKey, False);
end;

procedure TLbRSA.DecryptStream(InStream , OutStream : TStream);
  { decrypt stream data with RSA private key }
begin
  TRSA.RSAEncryptStream(InStream, OutStream, FPrivateKey, False);
end;

function TLbRSA.DecryptString(const InString : string) : string;
  { decrypt string data with RSA private key }
begin
  Result := GetString(TRSA.RSAEncryptBytes(GetBytes(InString), FPrivateKey, False));
end;

procedure TLbRSA.EncryptFile(const InFile, OutFile : string);
  { encrypt file data with RSA public key }
begin
  TRSA.RSAEncryptFile(InFile, OutFile, FPublicKey, True);
end;

procedure TLbRSA.EncryptStream(InStream, OutStream : TStream);
  { encrypt stream data with RSA public key }
begin
  TRSA.RSAEncryptStream(InStream, OutStream, FPublicKey, True);
end;

function TLbRSA.EncryptString(const InString : string) : string;
  { encrypt string data with RSA public key }
begin
  Result := GetString(TRSA.RSAEncryptBytes(GetBytes(InString), FPublicKey, True));
end;

procedure TLbRSA.GenerateKeyPair;
  { generate RSA public/private key pair }
begin
  if Assigned(FPrivateKey) then
    FPrivateKey.Free;
  if Assigned(FPublicKey) then
    FPublicKey.Free;
  try
    TRSA.GenerateRSAKeysEx(FPrivateKey, FPublicKey, FKeySize, FPrimeTestIterations, RSACallback);
  except
    raise Exception.Create(sRSAKeyPairErr);
  end;
end;

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

procedure TLbRSA.RSACallback(var Abort : Boolean);
  { pass callback on via OnProgress event }
begin
  Abort := False;
  if Assigned(OnProgress) then
    OnProgress(Self, Abort);
end;

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
const
  cDefHashMethod  = hmMD5;

begin
  inherited Create(AOwner);

  FPrivateKey := TLbRSAKey.Create(FKeySize);
  FPublicKey  := TLbRSAKey.Create(FKeySize);
  FSignature  := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  FHashMethod := cDefHashMethod;
  FPrimeTestIterations := cDefIterations;
end;

destructor TLbRSASSA.Destroy;
  { finalize }
begin
  FPrivateKey.Free;
  FPublicKey.Free;
  FSignature.Free;

  inherited Destroy;
end;

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

procedure TLbRSASSA.GenerateKeyPair;
  { generate RSA public/private key pair }
begin
  if Assigned(FPrivateKey) then
    FPrivateKey.Free;
  if Assigned(FPublicKey) then
    FPublicKey.Free;
  TRSA.GenerateRSAKeysEx(FPrivateKey, FPublicKey, FKeySize, FPrimeTestIterations, RSACallback);
end;

procedure TLbRSASSA.EncryptHash(const HashDigest; DigestLen : Cardinal);
  { encrypt message digest into signature }
begin
  if (FPrivateKey.Modulus.Size = 0) then                             {!!.02}
    raise Exception.Create(sRSAPrivateKeyErr);

  FSignature.CopyBuffer(HashDigest, DigestLen);
  TRSA.RSAEncryptBigInt(FSignature, FPrivateKey, bt01, True);             {!!.02}
end;

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
    TRSA.RSAEncryptBigInt(biBlock, FPublicKey, bt01, False);              {!!.02}
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

procedure TLbRSASSA.SignBuffer(const Buf; BufLen : Cardinal);
  { generate RSA signature of buffer data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        TMD5.HashMD5(MD5Digest, Buf, BufLen);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        TSHA1.HashSHA1(SHA1Digest, Buf, BufLen);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;

procedure TLbRSASSA.SignFile(const AFileName : string);
  { generate RSA signature of file data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        TMD5Encrypt.FileHashMD5(MD5Digest, AFileName);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        TSHA1Encrypt.FileHashSHA1(SHA1Digest, AFileName);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;

procedure TLbRSASSA.SignStream(AStream : TStream);
  { generate RSA signature of stream data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        TMD5Encrypt.StreamHashMD5(MD5Digest, AStream);
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        TSHA1Encrypt.StreamHashSHA1(SHA1Digest, AStream);
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;

procedure TLbRSASSA.SignString(const AStr : string);
  { generate RSA signature of string data }
var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
begin
  case FHashMethod of
    hmMD5  :
      begin
        TMD5.StringHashMD5(MD5Digest, GetBytes(AStr));
        EncryptHash(MD5Digest, SizeOf(MD5Digest));
      end;
    hmSHA1 :
      begin
        TSHA1Encrypt.StringHashSHA1(SHA1Digest, GetBytes(AStr));
        EncryptHash(SHA1Digest, SizeOf(SHA1Digest));
      end;
  end;
end;

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
        TMD5.HashMD5(MD5Digest2, Buf, BufLen);
        Result := CompareMem(@MD5Digest1, @MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        TSHA1Encrypt.HashSHA1(SHA1Digest2, Buf, BufLen);
        Result := CompareMem(@SHA1Digest1, @SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;

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
        TMD5Encrypt.FileHashMD5(MD5Digest2, AFileName);
        Result := CompareMem(@MD5Digest1, @MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        TSHA1Encrypt.FileHashSHA1(SHA1Digest2, AFileName);
        Result := CompareMem(@SHA1Digest1, @SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;

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
        TMD5Encrypt.StreamHashMD5(MD5Digest2, AStream);
        Result := CompareMem(@MD5Digest1, @MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        TSHA1Encrypt.StreamHashSHA1(SHA1Digest2, AStream);
        Result := CompareMem(@SHA1Digest1, @SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;

function TLbRSASSA.VerifyString(const AStr : string) : Boolean;
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
        TMD5Encrypt.StringHashMD5(MD5Digest2, GetBytes(AStr));
        Result := CompareMem(@MD5Digest1, @MD5Digest2, SizeOf(TMD5Digest));
      end;
    hmSHA1 :
      begin
        DecryptHash(SHA1Digest1, SizeOf(TSHA1Digest));
        TSHA1Encrypt.StringHashSHA1(SHA1Digest2, GetBytes(AStr));
        Result := CompareMem(@SHA1Digest1, @SHA1Digest2, SizeOf(TSHA1Digest));
      end;
  else
    Result := False;
  end;
end;

procedure TLbRSASSA.RSACallback(var Abort : Boolean);
  { pass callback on via OnProgress event }
begin
  Abort := False;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Abort);
end;

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


class function TRSA.DecryptRSA(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock; var OutBlock : TRSAPlainBlock): Longint;
  { decrypt ciphertext block with 512-bit RSA private key }
begin
  Result := DecryptRSA512(PrivateKey, InBlock, OutBlock);            {!!.02}
end;


{!!.02}
class function TRSA.DecryptRSA1024(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock1024; var OutBlock : TRSAPlainBlock1024): Longint;
  { decrypt ciphertext block with 1024-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks1024) then
    raise Exception.Create(sRSABlockSize1024Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;


{!!.02}
class function TRSA.DecryptRSA128(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock128; var OutBlock : TRSAPlainBlock128): Longint;
  { decrypt ciphertext block with 128-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks128) then
    raise Exception.Create(sRSABlockSize128Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;


{!!.02}
class function TRSA.DecryptRSA256(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock256; var OutBlock : TRSAPlainBlock256): Longint;
  { decrypt ciphertext block with 256-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks256) then
    raise Exception.Create(sRSABlockSize256Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;


{!!.02}
class function TRSA.DecryptRSA512(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock512; var OutBlock : TRSAPlainBlock512): Longint;
  { decrypt ciphertext block with 512-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks512) then
    raise Exception.Create(sRSABlockSize512Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;


{!!.02}
class function TRSA.DecryptRSA768(PrivateKey : TLbRSAKey; const InBlock : TRSACipherBlock768; var OutBlock : TRSAPlainBlock768): Longint;
  { decrypt ciphertext block with 768-bit RSA private key }
begin
  if (PrivateKey.KeySize <> aks768) then
    raise Exception.Create(sRSABlockSize768Err);
  Result := DecryptRSAEx(PrivateKey, @InBlock, @OutBlock);
end;


{!!.02}
class function TRSA.DecryptRSAEx(PrivateKey : TLbRSAKey; pInBlock, pOutBlock : PByteArray): Longint;
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


class function TRSA.EncryptRSA(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock; var OutBlock : TRSACipherBlock): Longint;
  { encrypt plaintext block with 512-bit RSA public key }
begin
  Result := EncryptRSA512(PublicKey, InBlock, OutBlock);             {!!.02}
end;


{!!.02}
class function TRSA.EncryptRSA1024(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock1024; var OutBlock : TRSACipherBlock1024): Longint;
  { encrypt plaintext block with 1024-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks1024) then
    raise Exception.Create(sRSABlockSize1024Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;


{!!.02}
class function TRSA.EncryptRSA128(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock128; var OutBlock : TRSACipherBlock128): Longint;
  { encrypt plaintext block with 128-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks128) then
    raise Exception.Create(sRSABlockSize128Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;


{!!.02}
class function TRSA.EncryptRSA256(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock256; var OutBlock : TRSACipherBlock256): Longint;
  { encrypt plaintext block with 256-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks256) then
    raise Exception.Create(sRSABlockSize256Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;


{!!.02}
class function TRSA.EncryptRSA512(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock512; var OutBlock : TRSACipherBlock512): Longint;
  { encrypt plaintext block with 512-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks512) then
    raise Exception.Create(sRSABlockSize512Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;


{!!.02}
class function TRSA.EncryptRSA768(PublicKey : TLbRSAKey; const InBlock : TRSAPlainBlock768; var OutBlock : TRSACipherBlock768): Longint;
  { encrypt plaintext block with 768-bit RSA public key }
begin
  if (PublicKey.KeySize <> aks768) then
    raise Exception.Create(sRSABlockSize768Err);
  Result := EncryptRSAEx(PublicKey, @InBlock, @OutBlock, SizeOf(InBlock));
end;


{!!.02}
class function TRSA.EncryptRSAEx(PublicKey : TLbRSAKey; pInBlock, pOutBlock : PByteArray; InDataSize : Integer): Longint;
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

{ == Public RSA routines =================================================== }
class procedure TRSA.GenerateRSAKeys(var PrivateKey, PublicKey : TLbRSAKey);
  { create RSA public/private key pair with default settings }
begin
  GenerateRSAKeysEx(PrivateKey, PublicKey, cLbDefAsymKeySize, cDefIterations, nil);
end;


class procedure TRSA.GenerateRSAKeysEx(var PrivateKey, PublicKey : TLbRSAKey; KeySize : TLbAsymKeySize; PrimeTestIterations : Byte; Callback : TLbRSACallback);
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

{ == Local RSA routines ==================================================== }
class procedure TRSA.RSADecodeBlock(biBlock : TLbBigInt);
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


class procedure TRSA.RSAEncryptBigInt(biBlock : TLbBigInt; Key : TLbRSAKey; BlockType : TRSABlockType; Encrypt : Boolean);
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


class procedure TRSA.RSAEncryptFile(const InFile, OutFile : string; Key : TLbRSAKey; Encrypt : Boolean);
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


class procedure TRSA.RSAEncryptStream(InStream, OutStream : TStream; Key : TLbRSAKey; Encrypt : Boolean);
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

class function TRSA.RSAEncryptBytes(const InBytes: TBytes; Key: TLbRSAKey; Encrypt: Boolean): TBytes;
var
  InStream  : TMemoryStream;
  OutStream : TMemoryStream;
  WorkStream : TMemoryStream;
begin
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  WorkStream := TMemoryStream.Create;
  InStream.Write(InBytes[0], Length(InBytes));
  InStream.Position := 0;

  if Encrypt then begin
    RSAEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    RSAEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class procedure TRSA.RSAFormatBlock(biBlock : TLbBigInt; BlockType : TRSABlockType);
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


end.

