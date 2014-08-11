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
{*                  LBDSA.PAS 2.08                       *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbDSA;
  {-DSA signature component and key classes}
                                                              
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
  Sysutils,
  LbRandom,
  LbCipher,
  LbBigInt,
  LbAsym,
  LbConst;

type
  TLbDSABlock = array[0..cBytes160-1] of Byte;   { same as TSHA1Digest }

type
  TLbGetDSABlockEvent = procedure(Sender : TObject; var Block : TLbDSABlock) of object;
  TLbDSACallback = procedure(var Abort : Boolean) of object;

{ TLbDSAParameters }
type
  TLbDSAParameters = class(TLbAsymmetricKey)
    protected
      FP : TLbBigInt;
      FQ : TLbBigInt;
      FG : TLbBigInt;
      F2Tog : TLbBigInt;
      FMostLeast : TLbBigInt;
      FPrimeTestIterations : Byte;
      FCallback : TLbDSACallback;
      function GenerateP(const ASeed : TLbDSABlock) : Boolean;
      function GenerateQ(const ASeed : TLbDSABlock) : Boolean;
      function GenerateG : Boolean;
      function GetPAsString : string;
      procedure SetPAsString(const Value : string);
      function GetQAsString : string;
      procedure SetQAsString(const Value : string);
      function GetGAsString : string;
      procedure SetGAsString(const Value : string);
      procedure SetKeySize(Value : TLbAsymKeySize); override;
    public {methods}
      constructor Create(aKeySize : TLbAsymKeySize); override;
      destructor Destroy; override;
      procedure Clear; virtual;
      procedure CopyDSAParameters(AKey : TLbDSAParameters);
      function GenerateDSAParameters(const ASeed : TLbDSABlock) : Boolean;
    public {properties}
      property P : TLbBigInt
        read FP;
      property Q : TLbBigInt
        read FQ;
      property G : TLbBigInt
        read FG;
      property PAsString : string
        read GetPAsString write SetPAsString;
      property QAsString : string
        read GetQAsString write SetQAsString;
      property GAsString : string
        read GetGAsString write SetGAsString;
      property PrimeTestIterations : Byte
        read FPrimeTestIterations write FPrimeTestIterations;
      property Callback : TLbDSACallback
        read FCallback write FCallback;
   end;


{ TLbDSAPrivateKey }
type
  TLbDSAPrivateKey = class(TLbDSAParameters)
    protected {private}
      FX    : TLbBigInt;
      FXKey : TLbDSABlock;
      function GetXAsString : string;
      procedure SetXAsString(const Value : string);

{!!.06}
      function  CreateASNKey(Input : pByteArray; Length : Integer) : Integer; override;
      function ParseASNKey(Input : pByte; Length : Integer) : boolean; override;
{!!.06}

    public {methods}
      constructor Create(aKeySize : TLbAsymKeySize); override;
      destructor Destroy; override;
      procedure Clear; override;
      procedure GenerateX(const AXKey : TLbDSABlock);
    public {properties}
      property X : TLbBigInt
        read FX;
      property XAsString : string
        read GetXAsString write SetXAsString;
   end;


{ TLbDSAPublicKey }
type
  TLbDSAPublicKey = class(TLbDSAParameters)
    protected {private}
      FY : TLbBigInt;
      function GetYAsString : string;
      procedure SetYAsString(const Value : string);

{!!.06}
      function  CreateASNKey(Input : pByteArray; Length : Integer) : Integer; override;
      function ParseASNKey(Input : pByte; Length : Integer) : boolean; override;
{!!.06}

    public {methods}
      constructor Create(aKeySize : TLbAsymKeySize); override;
      destructor Destroy; override;
      procedure Clear; override;
      procedure GenerateY(aX : TLbBigInt);
    public {properties}
      property Y : TLbBigInt
        read FY;
      property YAsString : string
        read GetYAsString write SetYAsString;
   end;


{ TLbDSA }
type
  TLbDSA = class(TLbSignature)
    protected {private}
      FPrivateKey : TLbDSAPrivateKey;
      FPublicKey : TLbDSAPublicKey;
      FPrimeTestIterations : Byte;
      FSignatureR : TLbBigInt;
      FSignatureS : TLbBigInt;
      FOnGetR     : TLbGetDSABlockEvent;
      FOnGetS     : TLbGetDSABlockEvent;
      FOnGetSeed  : TLbGetDSABlockEvent;
      FOnGetXKey  : TLbGetDSABlockEvent;
      FOnGetKKey  : TLbGetDSABlockEvent;
      FRandomSeed : Boolean;
      procedure SignHash(const ADigest : TSHA1Digest);
      function VerifyHash(const ADigest : TSHA1Digest) : Boolean;
      procedure SHA1KKey(var AKKey : TLbDSABlock);
      procedure RandomBlock(var ABlock : TLbDSABlock);
      procedure DoGetR;
      procedure DoGetS;
      procedure DoGetSeed(var ASeed : TLbDSABlock);
      procedure DoGetXKey(var AXKey : TLbDSABlock);
      procedure DoGetKKey(var AKKey : TLbDSABlock);
      procedure SetKeySize(Value : TLbAsymKeySize); override;
      procedure SetPrimeTestIterations(Value : Byte);
      procedure DSAParameterCallback(var Abort : Boolean);
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

      procedure Clear;
      function GeneratePQG : Boolean;
      procedure GenerateXY;

    public {properties}
      property PrivateKey : TLbDSAPrivateKey
        read FPrivateKey;
      property PublicKey : TLbDSAPublicKey
        read FPublicKey;
      property SignatureR : TLbBigInt
        read FSignatureR;
      property SignatureS : TLbBigInt
        read FSignatureS;

    published {properties}
      property PrimeTestIterations : Byte
        read FPrimeTestIterations write SetPrimeTestIterations;
      property KeySize;

    published {events}
      property OnGetR : TLbGetDSABlockEvent
        read FOnGetR write FOnGetR;
      property OnGetS : TLbGetDSABlockEvent
        read FOnGetS write FOnGetS;
      property OnGetSeed : TLbGetDSABlockEvent
        read FOnGetSeed write FOnGetSeed;
      property OnGetXKey : TLbGetDSABlockEvent
        read FOnGetXKey write FOnGetXKey;
      property OnGetKKey : TLbGetDSABlockEvent
        read FOnGetKKey write FOnGetKKey;
      property OnProgress : TLbProgressEvent
        read FOnProgress write FOnProgress;
    end;


implementation

uses
  LbProc, LbUtils;


const
  { 5 magic numbers for SHA-1 }
  SHA1_A = DWORD( $67452301 );
  SHA1_B = DWORD( $EFCDAB89 );
  SHA1_C = DWORD( $98BADCFE );
  SHA1_D = DWORD( $10325476 );
  SHA1_E = DWORD( $C3D2E1F0 );

  cZeroBlock : TLbDSABlock =
    (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);


{ == TLbDSAParameters =================================================== }
constructor TLbDSAParameters.Create(aKeySize : TLbAsymKeySize);
  { initialization }
begin
  inherited Create(aKeySize);
  FP := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  FQ := TLbBigInt.Create(SizeOf(TLbDSABlock));
  FG := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);

  { constant: 2^160 }
  F2Tog := TLbBigInt.Create(SizeOf(TLbDSABlock));
  F2Tog.CopyByte(1);
  F2Tog.Shl_(SizeOf(TLbDSABlock) * 8);

    { constant: 2^159 + 1 }
  FMostLeast := TLbBigInt.Create(SizeOf(TLbDSABlock));
  FMostLeast.Copy(F2Tog);
  FMostLeast.Shr_(1);
  FMostLeast.AddByte(1);

  FPrimeTestIterations := cDefIterations;
end;
{ -------------------------------------------------------------------------- }
destructor TLbDSAParameters.Destroy;
  { finalization }
begin
  FP.Free;
  FQ.Free;
  FG.Free;
  F2Tog.Free;
  FMostLeast.Free;
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAParameters.Clear;
  { reset everything }
begin
  FP.Clear;
  FQ.Clear;
  FG.Clear;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAParameters.SetKeySize(Value : TLbAsymKeySize);
  { DSA key must be between 512 and 1024 bits }
begin
  if (Value <> FKeySize) then begin
    if (Ord(Value) >= Ord(aks512)) and (Ord(Value) <= Ord(aks1024)) then
      FKeySize := Value
    else
      FKeySize := cLbDefAsymKeySize;
    FP.Clear;
    FQ.Clear;
    FG.Clear;
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GetPAsString : string;
  { return "big to little" hex string representation of p }
begin
  Result := FP.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAParameters.SetPAsString(const Value : string);
  { set p to value represented by "big to little" hex string }
var
  Buf : array[Byte] of Byte;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, cLbAsymKeyBytes[FKeySize]);
  FP.CopyBuffer(Buf, cLbAsymKeyBytes[FKeySize]);
  FP.Trim;
end;
{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GetQAsString : string;
  { return "big to little" hex string representation of q }
begin
  Result := FQ.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAParameters.SetQAsString(const Value : string);
  { set q to value represented by "big to little" hex string }
var
  Buf : TLbDSABlock;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, SizeOf(Buf));
  FQ.CopyBuffer(Buf, SizeOf(Buf));
  FQ.Trim;
end;
{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GetGAsString : string;
  { return "big to little" hex string representation of g }
begin
  Result := FG.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAParameters.SetGAsString(const Value : string);
  { set g to value represented by "big to little" hex string }
var
  Buf : array[Byte] of Byte;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, cLbAsymKeyBytes[FKeySize]);
  FG.CopyBuffer(Buf, cLbAsymKeyBytes[FKeySize]);
  FG.Trim;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAParameters.CopyDSAParameters(aKey : TLbDSAParameters);
  { assign paramters p, q, and g from another key }
begin
  FP.Copy(aKey.P);
  FQ.Copy(aKey.Q);
  FG.Copy(aKey.G);
end;
{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GenerateDSAParameters(const ASeed : TLbDSABlock) : Boolean;
  { generate paramaters p, q, and g }
begin
  Result := GenerateQ(ASeed);
  if Result then
    Result := GenerateP(ASeed);
  if Result then
    Result := GenerateG;
end;
{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GenerateQ(const ASeed : TLbDSABlock) : Boolean;
  { generate parameter q }
const
  MaxTries = 4096;                                                   {!!.06}
var
  U, SHAseed, SHAseed1 : TLbBigInt;
  Digest : TSHA1Digest;
  Counter : Word;                                                    {!!.06}
begin
  U := TLbBigInt.Create(SizeOf(TLbDSABlock));
  SHAseed := TLbBigInt.Create(SizeOf(TLbDSABlock));
  SHAseed1 := TLbBigInt.Create(SizeOf(TLbDSABlock));

  Counter := 0;
  try
    { Step 2: U = SHA(seed) xor SHA((seed+1) mod 2^g) }
    SHAseed.CopyBuffer(ASeed, SizeOf(ASeed));
    repeat
      FQ.Clear;
      {         SHA(Seed) }
      HashSHA1(Digest, SHAseed.IntBuf^, SHAseed.Size);
      SHAseed.CopyBuffer(Digest, SizeOf(Digest));    { SHASeed is big to little }
      SHAseed.ReverseBytes;                          { SHASeed -> little to big for math }

      {         SHA((seed+1) mod 2^g }
      SHAseed1.CopyBuffer(ASeed, SizeOf(ASeed));     { SHASeed1 is big to little }
      SHASeed1.ReverseBytes;                         { SHASeed1 -> little to big for math }
      SHAseed1.AddByte(1);
      SHAseed1.Modulus(F2Tog);
      SHASeed1.ReverseBytes;                         { SHASeed1 -> big to little for SHA }
      HashSHA1(Digest, SHAseed1.IntBuf^, SHAseed1.Size);
      SHAseed1.CopyBuffer(Digest, SizeOf(Digest));
      SHASeed1.ReverseBytes;                         { SHASeed1 -> little to big for math }

      {         U = SHASeed xor SHASeed1 }
      U.Copy(SHAseed);
      U.XOR_(SHAseed1);

      { Step 3: q = q or 2^159 or 1 }
      FQ.Copy(U);
      FQ.OR_(FMostLeast);

      { Step 4,5: fail if q is composite }
      Result := not FQ.IsComposite(FPrimeTestIterations);

      { if q is not composite then try again with another random seed }
      if not Result then begin
        Inc(Counter);
        SHASeed.RandomBytes(SizeOf(TLbDSABlock));
      end;
    until Result or (Counter >= MaxTries);
  finally
    U.Free;
    SHAseed.Free;
    SHAseed1.Free;
  end;
end;

{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GenerateP(const ASeed : TLbDSABlock) : Boolean;
  { generate parameter p }
const
  MaxTries = 4096;
var
  V, W, TwoToN, ModN, c, X : TLbBigInt;
  tmp : TLbBigInt;
  Lminus1, Counter : DWord;
  Offset : word;
  k, N, B : Byte;
  Digest : TSHA1Digest;
  Abort : Boolean;
  Prime : Boolean;
begin
  Abort := False;
  Prime := False;
  V      := TLbBigInt.Create(SizeOf(TLbDSABlock));
  W      := TLbBigInt.Create(SizeOf(TLbDSABlock));
  TwoToN := TLbBigInt.Create(SizeOf(TLbDSABlock));
  ModN   := TLbBigInt.Create(SizeOf(TLbDSABlock));
  c      := TLbBigInt.Create(SizeOf(TLbDSABlock));
  X      := TLbBigInt.Create(SizeOf(TLbDSABlock));
  tmp    := TLbBigInt.Create(SizeOf(TLbDSABlock));

  { L-1 = sizeof(P) - 1 }
  Lminus1 := (cLbAsymKeyBytes[FKeySize] * 8) - 1;
  N := Lminus1 div 160;
  B := Lminus1 mod 160;
  Counter := 0;
  Offset := 2;

  try
    while not (Prime or Abort) or (Counter > MaxTries) do begin
      { 2^0 }
      W.CopyByte(0);

      for k := 0 to n do begin
        { Step 7: V = SHA((seed+offset+k) mod 2^g) }
        V.CopyBuffer(ASeed, SizeOf(ASeed));  { V = Seed, is big to little }
        V.ReverseBytes;                      { V -> little to big for math }

        tmp.Clear;
        tmp.CopyDWord(k + Offset);
        V.Add( tmp );
        V.Modulus(F2Tog);

        V.ReverseBytes;                      { V -> big to little for SHA }
        HashSHA1(Digest, V.IntBuf^, V.Size);
        V.CopyBuffer(Digest, SizeOf(Digest));
        V.ReverseBytes;                      { V -> little to big for math }


        { Step 8: W = W + V*2^(160 * k) }
        if (k = n) then begin
          { mod last V to b bits }
          ModN.CopyByte( 1 );
          ModN.Shl_( b );
          V.Modulus(ModN);
        end;
        V.Shl_(160 * k);
        W.Add(V);
      end;

      { more Step 8: X = W + 2^(L-1) }
      TwoToN.CopyByte(1);
      TwoToN.Shl_(Lminus1);
      X.Copy(W);
      X.Add(TwoToN);

      { Step 9: c = X mod 2q }
      c.Copy(X);
      ModN.Copy(FQ);
      ModN.Shl_(1);
      c.Modulus(ModN);

      { more Step 9: p = X - (c - 1) }
      FP.Copy(X);
      FP.Subtract(c);
      FP.AddByte(1);

      { Step 10: fail if p < 2^(L-1) }
      if (FP.Compare(TwoToN) <> cLESS_THAN) then
        { Step 11: fail if p is composite }
      Prime := not FP.IsComposite(FPrimeTestIterations);

      { see if caller wants to abort }
      if not Prime then
        if Assigned(FCallBack) then
          FCallBack(Abort);

      { Step 13: bump counter and offset }
      Inc(Counter);
      Inc(Offset, n+1);
    end;
  finally
    V.Free;
    W.Free;
    TwoToN.Free;
    ModN.Free;
    X.Free;
    c.Free;
    tmp.Free;
  end;
  Result := Prime;
end;
{ -------------------------------------------------------------------------- }
function TLbDSAParameters.GenerateG : Boolean;
  { generate parameter g }
var
  h, p1q, tmp, c1 : TLbBigInt;
begin
  Result := False;
  if (FP.Size < 2) then
    Exit;

  h   := TLbBigInt.Create(20);
  p1q := TLbBigInt.Create(20);
  tmp := TLbBigInt.Create(20);
  c1 := TLbBigInt.Create(20);
  try
    c1.CopyByte(1);

    { (p-1)/q }
    p1q.Copy(FP);
    p1q.SubtractByte(1);
    p1q.Divide(FQ);

    h.CopyByte( $01 );
    repeat { until valid h }
      h.AddByte( $01 );
      tmp.Copy(h);
      tmp.PowerAndMod(p1q, FP);
    until (tmp.Compare(c1) = cGREATER_THAN);

    { g = h^((p-1)/q) }
    FG.Copy(h);
    FG.PowerAndMod(p1q, FP);
    Result := True;
  finally
    h.Free;
    p1q.Free;
    tmp.Free;
    c1.Free;
  end;
end;




{ == TLbDSAPrivateKey =================================================== }
constructor TLbDSAPrivateKey.Create(aKeySize : TLbAsymKeySize);
  {initialization }
begin
  inherited Create(aKeySize);
  FX := TLbBigInt.Create(SizeOf(TLbDSABlock));
  FillChar(FXKey, SizeOf(FXKey), #0);
end;
{ -------------------------------------------------------------------------- }
destructor TLbDSAPrivateKey.Destroy;
  { finalization }
begin
  FX.Free;
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAPrivateKey.Clear;
  { reset everything }
begin
  inherited Clear;
  FX.Clear;
  FillChar(FXKey, SizeOf(FXKey), #0);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAPrivateKey.GenerateX(const AXKey : TLbDSABlock);
  { generate parameter x }
var
  XVal : TSHA1Digest;
begin
  Move(AXKey, FXKey, SizeOf(FXKey));
  FillChar(XVal, SizeOf(XVal), #0);

  { X = SHA(XKey), XKey is big to little }
  HashSHA1(XVal, FXKey, SizeOf(FXKey));
  FX.CopyBuffer(XVal, SizeOf(XVal));
  FX.ReverseBytes;                         { X -> little to big for math }

  { X = XVal mod q, }
  FX.Modulus(FQ);
end;
{ -------------------------------------------------------------------------- }
function TLbDSAPrivateKey.GetXAsString : string;
  { return "big to little" hex string representation of x }
begin
  Result := FX.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAPrivateKey.SetXAsString(const Value : string);
  { set x to value represented by "big to little" hex string }
var
  Buf : TLbDSABlock;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, SizeOf(Buf));
  FX.CopyBuffer(Buf, SizeOf(Buf));
  FX.Trim;
end;
{ -------------------------------------------------------------------------- }
{!!.06}
function  TLbDSAPrivateKey.CreateASNKey(Input : pByteArray; Length : Integer) : Integer;
const
  TAG30 = $30;
var
  PSize : Integer;
  QSize : Integer;
  GSize : Integer;
  XSize : Integer;
  Total : Integer;
  pInput : PByteArray;
  Max : Integer;
begin
  pInput := Input;
  Max := Length;
  PSize := EncodeASN1(FP, pInput, Max);
  QSize := EncodeASN1(FQ, pInput, Max);
  GSize := EncodeASN1(FG, pInput, Max);
  XSize := EncodeASN1(FX, pInput, Max);
  Total := PSize + QSize + GSize + XSize;
  CreateASN1(Input^, Total, TAG30);
  Result := Total;
end;
{ -------------------------------------------------------------------------- }
{!!.06}
function TLbDSAPrivateKey.ParseASNKey(Input : PByte; Length : Integer ) : Boolean;
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
    raise Exception.Create(sDSAKeyBadKey);

  ParseASN1(pInput, Max, FP);
  ParseASN1(pInput, Max, FQ);
  ParseASN1(pInput, Max, FG);
  ParseASN1(pInput, Max, FX);

  Result := (Max = 0);
end;




{ == TLbDSAPublicKey ==================================================== }
constructor TLbDSAPublicKey.Create(aKeySize : TLbAsymKeySize);
  {initialization }
begin
  inherited Create(aKeySize);
  FY := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
end;
{ -------------------------------------------------------------------------- }
destructor TLbDSAPublicKey.Destroy;
  { finalization }
begin
  FY.Free;
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAPublicKey.Clear;
  { reset everything }
begin
  inherited Clear;
  FY.Clear;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAPublicKey.GenerateY(aX : TLbBigInt);
  { generate parameter y }
begin
  FY.Copy(FG);
  FY.PowerAndMod(aX, FP);
end;
{ -------------------------------------------------------------------------- }
function TLbDSAPublicKey.GetYAsString : string;
  { return "big to little" hex string representation of y }
begin
  Result := FY.IntStr;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSAPublicKey.SetYAsString(const Value : string);
  { set y to value represented by "big to little" hex string }
var
  Buf : array[Byte] of Byte;
begin
  FillChar(Buf, SizeOf(Buf), #0);
  HexToBuffer(Value, Buf, cLbAsymKeyBytes[FKeySize]);
  FY.CopyBuffer(Buf, cLbAsymKeyBytes[FKeySize]);
  FY.Trim;
end;
{ -------------------------------------------------------------------------- }
{!!.06}
function  TLbDSAPublicKey.CreateASNKey(Input : pByteArray; Length : Integer) : Integer;
const
  TAG30 = $30;
var
  PSize : Integer;
  QSize : Integer;
  GSize : Integer;
  YSize : Integer;
  Total : Integer;
  pInput : PByteArray;
  Max : Integer;
begin
  pInput := Input;
  Max := Length;
  PSize := EncodeASN1(FP, pInput, Max);
  QSize := EncodeASN1(FQ, pInput, Max);
  GSize := EncodeASN1(FG, pInput, Max);
  YSize := EncodeASN1(FY, pInput, Max);
  Total := PSize + QSize + GSize + YSize;
  CreateASN1(Input^, Total, TAG30);
  Result := Total;
end;
{ -------------------------------------------------------------------------- }
{!!.06}
function TLbDSAPublicKey.ParseASNKey(input : pByte; length : Integer) : Boolean;
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
    raise Exception.Create(sDSAKeyBadKey);

  ParseASN1(pInput, Max, FP);
  ParseASN1(pInput, Max, FQ);
  ParseASN1(pInput, Max, FG);
  ParseASN1(pInput, Max, FY);

  Result := (Max = 0);
end;


{ == TLbDSA ============================================================= }
constructor TLbDSA.Create(AOwner : TComponent);
  { initialization }
begin
  inherited Create(AOwner);

  FPrivateKey := TLbDSAPrivateKey.Create(FKeySize);
  FPrivateKey.Callback := DSAParameterCallback;
  FPublicKey  := TLbDSAPublicKey.Create(FKeySize);
  FPublicKey.Callback := DSAParameterCallback;
  FSignatureR := TLbBigInt.Create(SizeOf(TLbDSABlock));
  FSignatureS := TLbBigInt.Create(SizeOf(TLbDSABlock));
  FPrimeTestIterations := cDefIterations;
end;
{ -------------------------------------------------------------------------- }
destructor TLbDSA.Destroy;
  { finalization }
begin
  FPrivateKey.Free;
  FPublicKey.Free;
  FSignatureR.Free;
  FSignatureS.Free;

  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.Clear;
  { clear out everything }
begin
  FPrivateKey.Clear;
  FPublicKey.Clear;
  FSignatureR.Clear;
  FSignatureS.Clear;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SetKeySize(Value : TLbAsymKeySize);
  { DSA key must be between 512 and 1024 bits }
begin
  if (Value <> FKeySize) then begin
    if (Ord(Value) >= Ord(aks512)) and (Ord(Value) <= Ord(aks1024)) then
      FKeySize := Value
    else
      FKeySize := cLbDefAsymKeySize;
    FPrivateKey.KeySize := FKeySize;
    FPublicKey.KeySize := FKeySize;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SetPrimeTestIterations(Value : Byte);
  { set prime testing confidence level, 50 is plenty }
begin
  if (Value <> FPrimeTestIterations) then begin
    FPrimeTestIterations := Value;
    FPrivateKey.PrimeTestIterations := Value;
    FPublicKey.PrimeTestIterations := Value;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.DSAParameterCallback(var Abort : Boolean);
  { pass callback on via OnProgress event }
begin
  Abort := False;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Abort);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.RandomBlock(var ABlock : TLbDSABlock);
  { fill block with random bytes }
begin
  with TLbRandomGenerator.Create do
    try
      RandomBytes(ABlock, SizeOf(ABlock));
    finally
      Free;
    end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.DoGetSeed(var ASeed : TLbDSABlock);
  { fire OnGetSeed event to obtain seed, randomize if necessary }
begin
  FillChar(ASeed, SizeOf(ASeed), #0);
  if Assigned(FOnGetSeed) then
    FOnGetSeed(Self, ASeed);

  if CompareBuffers(ASeed, cZeroBlock, SizeOf(ASeed)) then
    RandomBlock(ASeed);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.DoGetXKey(var AXKey : TLbDSABlock);
  { fire OnGetXKey event to obtain XKey, randomize if necessary }
begin
  FillChar(AXKey, SizeOf(AXKey), #0);
  if Assigned(FOnGetXKey) then
    FOnGetXKey(Self, AXKey);

  if CompareBuffers(AXKey, cZeroBlock, SizeOf(AXKey)) then
    RandomBlock(AXKey);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.DoGetKKey(var AKKey : TLbDSABlock);
  { fire OnGetKKey event to obtain KKey, randomize if necessary }
begin
  FillChar(AKKey, SizeOf(AKKey), #0);
  if Assigned(FOnGetKKey) then
    FOnGetKKey(Self, AKKey);

  if CompareBuffers(AKKey, cZeroBlock, SizeOf(AKKey)) then
    RandomBlock(AKKey);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SHA1KKey(var AKKey : TLbDSABlock);
  { SHA(KKey) requires special magic number sequence }
var
  Context : TSHA1Context;
  Digest : TSHA1Digest;
begin
  Fillchar(Context, SizeOf(Context), #0);
  Context.sdHash[ 0 ] := SHA1_B;
  Context.sdHash[ 1 ] := SHA1_C;
  Context.sdHash[ 2 ] := SHA1_D;
  Context.sdHash[ 3 ] := SHA1_E;
  Context.sdHash[ 4 ] := SHA1_A;

  UpdateSHA1(Context, AKKey, SizeOf(AKKey));
  FinalizeSHA1(Context, Digest);
  Move(Digest, AKKey, SizeOf(AKKey));
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.DoGetR;
  { fire OnGetR event to obtain signature(R) }
var
  R : TLbDSABlock;
begin
  FillChar(R, SizeOf(R), #0);
  if Assigned(FOnGetR) then begin
    FOnGetR(Self, R);
    FSignatureR.CopyBuffer(R, SizeOf(R));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.DoGetS;
  { fire OnGetS event to obtain signature(S) }
var
  S : TLbDSABlock;
begin
  FillChar(S, SizeOf(S), #0);
  if Assigned(FOnGetS) then begin
    FOnGetS(Self, S);
    FSignatureS.CopyBuffer(S, SizeOf(S));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.GenerateKeyPair;
  { generate public and private key parameters p, q, g, x, and y }
begin
  GeneratePQG;
  GenerateXY;
end;
{ -------------------------------------------------------------------------- }
function TLbDSA.GeneratePQG : Boolean;
  { generate parameters p, q, and g }
var
  Seed : TLbDSABlock;
begin
  DoGetSeed(Seed);
  try
    Result := FPrivateKey.GenerateDSAParameters(Seed);
    if Result then
      FPublicKey.CopyDSAParameters(FPrivateKey);
  except
    raise Exception.Create(sDSAParametersPQGErr);
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.GenerateXY;
  { generate parameters x and y }
var
  XKey : TLbDSABlock;
begin
  DoGetXKey(XKey);
  try
    FPrivateKey.GenerateX(XKey);
    FPublicKey.GenerateY(FPrivateKey.X);
  except
    raise Exception.Create(sDSAParametersXYErr);
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SignHash(const ADigest : TSHA1Digest);
  { generate signature(r, s) of message hash }
var
  K : TLbBigInt;
  XR : TLbBigInt;
  KKey : TLbDSABlock;
begin
  K := TLbBigInt.Create(SizeOf(TLbDSABlock));
  XR := TLbBigInt.Create(SizeOf(TLbDSABlock));
  DoGetKKey(KKey);
  try
    K.CopyBuffer(KKey, SizeOf(KKey));
    K.Modulus(FPrivateKey.Q);                                        {!!.06}
    { r = (g^k mod p) mod q }
    with FSignatureR do begin
      Copy(FPrivateKey.G);
      PowerAndMod(K, FPrivateKey.P);
      Modulus(FPrivateKey.Q);
      if FSignatureR.IsZero then
        raise Exception.Create(sDSASignatureZeroR);
    end;

    { compute k^(-1) and xr }
    K.ModInv(FPrivateKey.Q);
    XR.Copy(FPrivateKey.X);
    XR.Multiply(FSignatureR);

    { s = (k^(-1)(SHA(M) + xr)) mod q }
    with FSignatureS do begin
      CopyBuffer(ADigest, SizeOf(ADigest));     { s = SHA(M) is big to little }
      ReverseBytes;                             { s -> little to big for math }
      Add(XR);
      Multiply(K);
      Modulus(FPrivateKey.Q);
      if FSignatureS.IsZero then
        raise Exception.Create(sDSASignatureZeroS);
    end;
  except
    K.Free;
    XR.Free;
    raise Exception.Create(sDSASignatureErr);
  end;
  K.Free;
  XR.Free;
end;
{ -------------------------------------------------------------------------- }
function TLbDSA.VerifyHash(const ADigest : TSHA1Digest) : Boolean;
  { verify signature(r, s) against message hash }
var
  W, U1, U2, V, V2 : TLbBigInt;
begin
  W  := TLbBigInt.Create(20);
  U1 := TLbBigInt.Create(20);
  U2 := TLbBigInt.Create(20);
  V  := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  V2 := TLbBigInt.Create(cLbAsymKeyBytes[FKeySize]);
  DoGetR;
  DoGetS;
  try
    { w = s^(-1) mod q }
    with W do begin
      Copy(FSignatureS);
      ModInv(FPublicKey.Q);
    end;

    { u1 = (SHA(M)*w) mod q }
    with U1 do begin
      CopyBuffer(ADigest, SizeOf(ADigest));    { U1 = SHA(M) is big to little }
      ReverseBytes;                            { U1 -> little to big for math }
      Multiply(W);
      Modulus(FPublicKey.Q);
    end;

    { u2 = (r*w) mod q }
    with U2 do begin
      Copy(FSignatureR);
      Multiply(W);
      Modulus(FPublicKey.Q);
    end;

    { v = ((g^u1 * y^u2) mod p) mod q }
    V.Copy(FPublicKey.Y);
    V.PowerAndMod(U2, FPublicKey.P);
    V2.Copy(FPublicKey.G);
    V2.PowerAndMod(U1, FPublicKey.P);
    V.Multiply(V2);
    V.Modulus(FPublicKey.P);
    V.Modulus(FPublicKey.Q);

    { signature valid when v = r }
    Result := V.Compare(FSignatureR) = cEQUAL_TO;
  except
    Result := False;
  end;
  W.Free;
  U1.Free;
  U2.Free;
  V.Free;
  V2.Free;
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SignBuffer(const Buf; BufLen : Cardinal);
  { generate DSA signature of buffer data }
var
  Digest : TSHA1Digest;
begin
  HashSHA1(Digest, Buf, BufLen);
  SignHash(Digest);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SignFile(const AFileName : string);
  { generate DSA signature of file data }
var
  Digest : TSHA1Digest;
begin
  FileHashSHA1(Digest, AFileName);
  SignHash(Digest);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SignStream(AStream : TStream);
  { generate DSA signature of stream data }
var
  Digest : TSHA1Digest;
begin
  StreamHashSHA1(Digest, AStream);
  SignHash(Digest);
end;
{ -------------------------------------------------------------------------- }
procedure TLbDSA.SignStringA(const AStr : AnsiString);
  { generate DSA signature of string data }
var
  Digest : TSHA1Digest;
begin
  StringHashSHA1A(Digest, AStr);
  SignHash(Digest);
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure TLbDSA.SignStringW(const AStr : UnicodeString);
  { generate DSA signature of string data }
var
  Digest : TSHA1Digest;
begin
  StringHashSHA1W(Digest, AStr);
  SignHash(Digest);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
function TLbDSA.VerifyBuffer(const Buf; BufLen : Cardinal) : Boolean;
  { verify DSA signature agrees with buffer data }
var
  Digest : TSHA1Digest;
begin
  HashSHA1(Digest, Buf, BufLen);
  Result := VerifyHash(Digest);
end;
{ -------------------------------------------------------------------------- }
function TLbDSA.VerifyFile(const AFileName : string) : Boolean;
  { verify DSA signature agrees with file data }
var
  Digest : TSHA1Digest;
begin
  FileHashSHA1(Digest, AFileName);
  Result := VerifyHash(Digest);
end;
{ -------------------------------------------------------------------------- }
function TLbDSA.VerifyStream(AStream : TStream) : Boolean;
  { verify DSA signature agrees with stream data }
var
  Digest : TSHA1Digest;
begin
  StreamHashSHA1(Digest, AStream);
  Result := VerifyHash(Digest);
end;
{ -------------------------------------------------------------------------- }
function TLbDSA.VerifyStringA(const AStr : AnsiString) : Boolean;
  { verify DSA signature agrees with string data }
var
  Digest : TSHA1Digest;
begin
  StringHashSHA1A(Digest, AStr);
  Result := VerifyHash(Digest);
end;

{$IFDEF UNICODE}
function TLbDSA.VerifyStringW(const AStr : UnicodeString) : Boolean;
  { verify DSA signature agrees with string data }
var
  Digest : TSHA1Digest;
begin
  StringHashSHA1W(Digest, AStr);
  Result := VerifyHash(Digest);
end;
{$ENDIF}

end.
