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
{*                  LBCIPHER.PAS 2.08                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbCipher;
  {-private key encryption/decryption primitives}

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
  Classes;
const
  { largest structure that can be created }
  MaxStructSize = 1024 * 2000000; {2G}


{ TLbBase - used to force this unit to be added to uses clause }
type
  TLBBase = class(TComponent)
  end;

{$IFDEF LINUX}
  pDword = ^dword;
{$ENDIF}


{ general structures }
type
  pLongIntArray = ^TLongIntArray;
  TLongIntArray = array [0..MaxStructSize div SizeOf(LongInt) - 1] of LongInt;

  TLongIntRec = packed record
    case Byte of
      1: (Lo: Word;
          Hi: Word);
      2: (LoLo: Byte;
          LoHi: Byte;
          HiLo: Byte;
          HiHi: Byte);
  end;

  TInt64 = packed record
    case Byte of
      0: (Lo: LongInt;
          Hi: LongInt);
      1: (LoLo: Word;
          LoHi: Word;
          HiLo: Word;
          HiHi: Word);
      2: (LoLoLo: Byte;
          LoLoHi: Byte;
          LoHiLo: Byte;
          LoHiHi: Byte;
          HiLoLo: Byte;
          HiLoHi: Byte;
          HiHiLo: Byte;
          HiHiHi: Byte);
  end;

  TRDLVector = record
    case Byte of
      0 : (dw : DWord);
      1 : (bt : array[0..3] of Byte);
    end;


{ encryption key types }
type
  PKey64  = ^TKey64;                                                 {!!.03}
  TKey64  = array [0..7] of Byte;

  PKey128 = ^TKey128;                                                {!!.03}
  TKey128 = array [0..15] of Byte;

  PKey192 = ^TKey192;                                                {!!.03}
  TKey192 = array [0..23] of Byte;

  PKey256 = ^TKey256;                                                {!!.03}
  TKey256 = array [0..31] of Byte;


{ encryption block types }
type
  PLBCBlock  = ^TLBCBlock;
  TLBCBlock  = array[0..3] of LongInt;     { LockBox Cipher }
  TDESBlock  = array[0..7] of Byte;        { DES }
  TLQCBlock  = array[0..1] of LongInt;     { LockBox Quick Cipher }
  TBFBlock   = array[0..1] of LongInt;     { BlowFish }
  TRDLBlock  = array[0..15] of Byte;       { Rijndael }


{ context type constants }
const
  BFRounds = 16;      { 16 blowfish rounds }
  MaxRDLRounds = 14;  { 14 Rijndael rounds }


{ block cipher context types }
type
  { Blowfish }
  TBFContext = packed record
    PBox    : array[0..(BFRounds+1)] of LongInt;
    SBox    : array[0..3, 0..255] of LongInt;
  end;

  { DES }
  TDESContext = packed record
    TransformedKey : array [0..31] of LongInt;
    Encrypt        : Boolean;
  end;

  { 3 DES }
  TTripleDESContext = array [0..1] of TDESContext;
  TTripleDESContext3Key = array [0..2] of TDESContext;               {!!.01}

  { LockBox Cipher }
  TLBCContext = packed record
    Encrypt : Boolean;
    Dummy   : array[0..2] of Byte; {filler}
    Rounds  : LongInt;
    case Byte of
      0: (SubKeys64   : array [0..15] of TKey64);
      1: (SubKeysInts : array [0..3, 0..7] of LongInt);
  end;

  { Rijndael }
  TRDLContext = packed record
    Encrypt : Boolean;
    Dummy   : array[0..2] of Byte; {filler}
    Rounds  : DWord;
    case Byte of
      0 : (W  : array[0..(MaxRDLRounds * 4)] of TRDLVector);
      1 : (Rk : array[0..MaxRDLRounds] of TRDLBlock);
    end;


{ stream cipher context types }
type
  { LockBox stream cipher }
  TLSCContext = packed record
    Index       : LongInt;
    Accumulator : LongInt;
    SBox        : array [0..255] of Byte;
  end;

  { random number stream ciphers }
  TRNG32Context = array [0..3] of Byte;
  TRNG64Context = array [0..7] of Byte;


{ message digest blocks }
type
  TMD5Digest  = array [0..15] of Byte;         { 128 bits - MD5 }
  TSHA1Digest = array [0..19] of Byte;         { 160 bits - SHA-1 }


{ message digest context types }
type
  TLMDContext  = array [0..279] of Byte;       { LockBox message digest }
  TMD5Context  = array [0..87] of Byte;        { MD5 }
  TSHA1Context = record                        { SHA-1 }
    sdHi    : DWord;
    sdLo    : DWord;
    sdIndex : DWord;
    sdHash  : array [0..4] of DWord;
    sdBuf   : array [0..63] of Byte;
  end;


{ Blowfish Cipher }
procedure InitEncryptBF(Key : TKey128;
            var Context : TBFContext);
procedure EncryptBF(const Context : TBFContext;
            var Block : TBFBlock; Encrypt : Boolean);
procedure EncryptBFCBC(const Context : TBFContext;
            const Prev : TBFBlock; var Block : TBFBlock; Encrypt : Boolean);

{ DES Cipher }
procedure InitEncryptDES(const Key : TKey64;
            var Context : TDESContext;  Encrypt : Boolean); 
procedure EncryptDES(const Context : TDESContext;
            var Block : TDESBlock); 
procedure EncryptDESCBC(const Context : TDESContext;
            const Prev : TDESBlock;  var Block : TDESBlock); 

{ Triple DES Cipher }
procedure InitEncryptTripleDES(const Key : TKey128;
            var Context : TTripleDESContext; Encrypt : Boolean);
procedure EncryptTripleDES(const Context : TTripleDESContext;
            var Block : TDESBlock);
procedure EncryptTripleDESCBC(const Context : TTripleDESContext;
            const Prev : TDESBlock; var Block : TDESBlock);

{!!.01}
{ Triple DES Cipher 3 Key }
procedure InitEncryptTripleDES3Key(const Key1, Key2, Key3 : TKey64;
            var Context : TTripleDESContext3Key; Encrypt : Boolean);
procedure EncryptTripleDES3Key(const Context : TTripleDESContext3Key;
            var Block : TDESBlock);
procedure EncryptTripleDESCBC3Key(const Context : TTripleDESContext3Key;
            const Prev : TDESBlock; var Block : TDESBlock);
{!!.01}

{ LockBox Cipher }
procedure InitEncryptLBC(const Key : TKey128;
            var Context : TLBCContext; Rounds : LongInt; Encrypt : Boolean); 
procedure EncryptLBC(const Context : TLBCContext;
            var Block : TLBCBlock); 
procedure EncryptLBCCBC(const Context : TLBCContext;
            const Prev : TLBCBlock; var Block : TLBCBlock); 

{ LockBox Quick Cipher }
procedure EncryptLQC(const Key : TKey128;
            var Block : TLQCBlock; Encrypt : Boolean); 
procedure EncryptLQCCBC(const Key : TKey128;
            const Prev : TLQCBlock; var Block : TLQCBlock; Encrypt : Boolean); 

{ LockBox Stream Cipher }
procedure InitEncryptLSC(const Key; KeySize : Integer;
            var Context : TLSCContext); 
procedure EncryptLSC(var Context : TLSCContext;
            var Buf; BufSize : LongInt); 

{ Random Number Cipher }
procedure InitEncryptRNG64(KeyHi, KeyLo : LongInt;
            var Context : TRNG64Context); 
procedure EncryptRNG32(var Context : TRNG32Context;
            var Buf; BufSize : LongInt); 
procedure EncryptRNG64(var Context : TRNG64Context;
            var Buf; BufSize : LongInt); 
procedure InitEncryptRNG32(Key : LongInt;
            var Context : TRNG32Context); 

{ Rijndael Cipher }
procedure InitEncryptRDL(const Key; KeySize : Longint;
            var Context : TRDLContext; Encrypt : Boolean);
procedure EncryptRDL(const Context : TRDLContext;
            var Block : TRDLBlock); 
procedure EncryptRDLCBC(const Context : TRDLContext;
            const Prev : TRDLBlock; var Block : TRDLBlock); 

{ MD5 message digest }
procedure InitMD5(var Context : TMD5Context); 
procedure HashMD5(var Digest : TMD5Digest;
            const Buf; BufSize : LongInt); 
procedure FinalizeMD5(var Context : TMD5Context;
            var Digest : TMD5Digest); 
procedure UpdateMD5(var Context : TMD5Context;
            const Buf;  BufSize : LongInt); 

{ LockBox message digest }
procedure InitLMD(var Context : TLMDContext); 
procedure HashLMD(var Digest; DigestSize : LongInt;
            const Buf; BufSize : LongInt); 
procedure FinalizeLMD(var Context : TLMDContext;
            var Digest; DigestSize : LongInt); 
procedure UpdateLMD(var Context : TLMDContext;
            const Buf; BufSize : LongInt); 

{ SHA-1 message digest }
procedure InitSHA1(var Context: TSHA1Context); 
procedure HashSHA1(var Digest : TSHA1Digest;
            const Buf; BufSize : Longint); 
procedure UpdateSHA1(var Context : TSHA1Context;
            const Buf; BufSize: Longint); 
procedure FinalizeSHA1(var Context: TSHA1Context;
            var Digest : TSHA1Digest);

{ Miscellaneous hash algorithms }
procedure HashELF(var Digest : LongInt;
            const Buf;  BufSize : LongInt);
procedure HashMix128(var Digest : LongInt;
            const Buf;  BufSize : LongInt);

{ String hashing }
procedure StringHashELF(var Digest : LongInt;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
procedure StringHashLMD(var Digest; DigestSize : LongInt;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
procedure StringHashMD5(var Digest : TMD5Digest;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
procedure StringHashMix128(var Digest : LongInt;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
procedure StringHashSHA1(var Digest : TSHA1Digest;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});

{$IFDEF UNICODE} // only for Tiburon
procedure StringHashELFW(var Digest : LongInt;
            const Str : UnicodeString);
procedure StringHashLMDW(var Digest; DigestSize : LongInt;
            const Str : UnicodeString);
procedure StringHashMD5W(var Digest : TMD5Digest;
            const Str : UnicodeString);
procedure StringHashMix128W(var Digest : LongInt;
            const Str : UnicodeString);
procedure StringHashSHA1W(var Digest : TSHA1Digest;
            const Str : UnicodeString);
{$ENDIF}

procedure StringHashELFA(var Digest : LongInt;
            const Str : AnsiString);
procedure StringHashLMDA(var Digest; DigestSize : LongInt;
            const Str : AnsiString);
procedure StringHashMD5A(var Digest : TMD5Digest;
            const Str : AnsiString);
procedure StringHashMix128A(var Digest : LongInt;
            const Str : AnsiString);
procedure StringHashSHA1A(var Digest : TSHA1Digest;
            const Str : AnsiString);

{ Key generation }
procedure GenerateLMDKey(var Key; KeySize : Integer;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
procedure GenerateMD5Key(var Key : TKey128;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
procedure GenerateRandomKey(var Key; KeySize : Integer);

{$IFDEF UNICODE}
procedure GenerateLMDKeyW(var Key; KeySize : Integer; const Str : UnicodeString);
procedure GenerateMD5KeyW(var Key : TKey128; const Str : UnicodeString);
{$ENDIF}
procedure GenerateLMDKeyA(var Key; KeySize : Integer; const Str : AnsiString);
procedure GenerateMD5KeyA(var Key : TKey128; const Str : AnsiString);

{ Misc public utilities }
function Ran01(var Seed : LongInt) : LongInt;
function Ran02(var Seed : LongInt) : LongInt; 
function Ran03(var Seed : LongInt) : LongInt; 
function Random32Byte(var Seed : LongInt) : Byte; 
function Random64Byte(var Seed : TInt64) : Byte; 
procedure ShrinkDESKey(var Key : TKey64); 
procedure XorMem(var Mem1;  const Mem2;  Count : Cardinal); 
function RolX(I, C : DWord) : DWord; register;

implementation

uses
  LbUtils, SysUtils;


{first 2048 bits of Pi in hexadecimal, low to high, without the leading "3"}
const
  Pi2048: array [0..255] of Byte = (
    $24, $3F, $6A, $88, $85, $A3, $08, $D3, $13, $19, $8A, $2E, $03, $70, $73, $44,
    $A4, $09, $38, $22, $29, $9F, $31, $D0, $08, $2E, $FA, $98, $EC, $4E, $6C, $89,
    $45, $28, $21, $E6, $38, $D0, $13, $77, $BE, $54, $66, $CF, $34, $E9, $0C, $6C,
    $C0, $AC, $29, $B7, $C9, $7C, $50, $DD, $3F, $84, $D5, $B5, $B5, $47, $09, $17,
    $92, $16, $D5, $D9, $89, $79, $FB, $1B, $D1, $31, $0B, $A6, $98, $DF, $B5, $AC,
    $2F, $FD, $72, $DB, $D0, $1A, $DF, $B7, $B8, $E1, $AF, $ED, $6A, $26, $7E, $96,
    $BA, $7C, $90, $45, $F1, $2C, $7F, $99, $24, $A1, $99, $47, $B3, $91, $6C, $F7,
    $08, $01, $F2, $E2, $85, $8E, $FC, $16, $63, $69, $20, $D8, $71, $57, $4E, $69,
    $A4, $58, $FE, $A3, $F4, $93, $3D, $7E, $0D, $95, $74, $8F, $72, $8E, $B6, $58,
    $71, $8B, $CD, $58, $82, $15, $4A, $EE, $7B, $54, $A4, $1D, $C2, $5A, $59, $B5,
    $9C, $30, $D5, $39, $2A, $F2, $60, $13, $C5, $D1, $B0, $23, $28, $60, $85, $F0,
    $CA, $41, $79, $18, $B8, $DB, $38, $EF, $8E, $79, $DC, $B0, $60, $3A, $18, $0E,
    $6C, $9E, $0E, $8B, $B0, $1E, $8A, $3E, $D7, $15, $77, $C1, $BD, $31, $4B, $27,
    $78, $AF, $2F, $DA, $55, $60, $5C, $60, $E6, $55, $25, $F3, $AA, $55, $AB, $94,
    $57, $48, $98, $62, $63, $E8, $14, $40, $55, $CA, $39, $6A, $2A, $AB, $10, $B6,
    $B4, $CC, $5C, $34, $11, $41, $E8, $CE, $A1, $54, $86, $AF, $7C, $72, $E9, $93);

type
  pMD5ContextEx = ^TMD5ContextEx;
  TMD5ContextEx = packed record
    Count : array [0..1] of DWord;  {number of bits handled mod 2^64}  
    State : array [0..3] of DWord;  {scratch buffer}                   
    Buf   : array [0..63] of Byte;    {input buffer}
  end;

  TLMDContextEx = packed record
    DigestIndex : LongInt;
    Digest      : array [0..255] of Byte;
    KeyIndex    : LongInt;
    case Byte of
      0: (KeyInts : array [0..3] of LongInt);
      1: (Key     : TKey128);
  end;
  TBlock2048 = array [0..255] of Byte;

type
  {bit mixing types}
  T128Bit     = array [0..3] of DWord;
  T256Bit     = array [0..7] of DWord;                                 

const
  BCSalts: array [0..3] of DWord =                                     
    ($55555555, $AAAAAAAA, $33333333, $CCCCCCCC);

type
  TBCHalfBlock = array [0..1] of LongInt;

  TBFBlockEx = packed record
    Xl : array[0..3] of Byte;
    Xr : array[0..3] of Byte;
  end;

{ Blowfish tables }
{$I LbBF.inc }                                                       {!!.01}

{ SHA-1 constants }
const
  { 5 magic numbers }
  SHA1_A = DWORD( $67452301 );
  SHA1_B = DWORD( $EFCDAB89 );
  SHA1_C = DWORD( $98BADCFE );
  SHA1_D = DWORD( $10325476 );
  SHA1_E = DWORD( $C3D2E1F0 );
  { four rounds consts }
  SHA1_K1 = DWORD( $5A827999 );
  SHA1_K2 = DWORD( $6ED9EBA1 );
  SHA1_K3 = DWORD( $8F1BBCDC );
  SHA1_K4 = DWORD( $CA62C1D6 );
  { Maskes used in byte swap }
  LBMASK_HI = DWORD( $FF0000 );
  LBMASK_LO = DWORD( $FF00 );


{ Rijndael constants }
const
  RDLNb128 = 4;      { 128 bit block }
  RDLNb192 = 6;      { 192 bit block (not used) }
  RDLNb256 = 8;      { 256 bit block (not used) }

  RDLNk128 = 4;      { 128 bit key }
  RDLNk192 = 6;      { 192 bit key }
  RDLNk256 = 8;      { 256 bit key }

{ Rijndael structures }
type
  TRDLVectors = array[0..(RDLNb128 - 1)] of TRDLVector;
  TRDLMixColMatrix = array[0..3, 0..3] of Byte;

{ Rijndael tables }
{$I LbRDL.inc}                                                       {!!.01}


{ ========================================================================== }
procedure EncryptLBC(const Context : TLBCContext; var Block : TLBCBlock);
var
  Blocks    : array[0..1] of TBCHalfBlock;                           {!!.01}
  Work      : TBCHalfBlock;
  Right     : TBCHalfBlock;
  Left      : TBCHalfBlock;
  AA, BB    : LongInt;
  CC, DD    : LongInt;
  R, T      : LongInt;
begin
  Move(Block, Blocks, SizeOf(Blocks));                               {!!.01}
  Right := Blocks[0];
  Left := Blocks[1];

  for R := 0 to Context.Rounds - 1 do begin
    {transform the right side}
    AA := Right[0];
    BB := TBCHalfBlock(Context.SubKeys64[R])[0];
    CC := Right[1];
    DD := TBCHalfBlock(Context.SubKeys64[R])[1];

    {mix it once...}
    AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 7);
    BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 13);
    CC := CC + BB; BB := BB + CC; CC := CC xor (CC shr 17);
    DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 9);
    AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 3);
    BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 7);
    CC := CC + BB; BB := BB + CC; CC := CC xor (DD shr 15);
    DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 11);

    {swap sets...}
    T := AA; AA := CC; CC := T;
    T := BB; BB := DD; DD := T;

    {mix it twice}
    AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 7);
    BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 13);
    CC := CC + BB; BB := BB + CC; CC := CC xor (CC shr 17);
    DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 9);
    AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 3);
    BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 7);
    CC := CC + BB; BB := BB + CC; CC := CC xor (DD shr 15);
    DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 11);

    Work[0] := Left[0] xor AA xor BB;
    Work[1] := Left[1] xor CC xor DD;

    Left := Right;
    Right := Work;
  end;

  Blocks[0] := Left;
  Blocks[1] := Right;
  Move(Blocks, Block, SizeOf(Block));                                {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure EncryptLBCCBC(const Context : TLBCContext; const Prev : TLBCBlock; var Block : TLBCBlock);
begin
  if Context.Encrypt then begin
    XorMem(Block, Prev, SizeOf(Block));
    EncryptLBC(Context, Block);
  end else begin
    EncryptLBC(Context, Block);
    XorMem(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptDES(const Key : TKey64; var Context : TDESContext;  Encrypt : Boolean);
const
  PC1        : array [0..55] of Byte =
    (56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26,
     18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
     13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3);
  PC2        : array [0..47] of Byte =
    (13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7,
     15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
     43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31);
  CTotRot    : array [0..15] of Byte = (1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28);
  CBitMask   : array [0..7] of Byte = (128, 64, 32, 16, 8, 4, 2, 1);
var
  PC1M       : array [0..55] of Byte;
  PC1R       : array [0..55] of Byte;
  KS         : array [0..7] of Byte;
  I, J, L, M : LongInt;
begin
  {convert PC1 to bits of key}
  for J := 0 to 55 do begin
    L := PC1[J];
    M := L mod 8;
    PC1M[J] := Ord((Key[L div 8] and CBitMask[M]) <> 0);
  end;

  {key chunk for each iteration}
  for I := 0 to 15 do begin
    {rotate PC1 the right amount}
    for J := 0 to 27 do begin
      L := J + CTotRot[I];
      if (L < 28) then begin
        PC1R[J] := PC1M[L];
        PC1R[J + 28] := PC1M[L + 28];
      end else begin
        PC1R[J] := PC1M[L - 28];
        PC1R[J + 28] := PC1M[L];
      end;
    end;

    {select bits individually}
    FillChar(KS, SizeOf(KS), 0);
    for J := 0 to 47 do
      if Boolean(PC1R[PC2[J]]) then begin
        L := J div 6;
        KS[L] := KS[L] or CBitMask[J mod 6] shr 2;
      end;

    {now convert to odd/even interleaved form for use in F}
    if Encrypt then begin
      Context.TransformedKey[I * 2] := (LongInt(KS[0]) shl 24) or (LongInt(KS[2]) shl 16) or
        (LongInt(KS[4]) shl 8) or (LongInt(KS[6]));
      Context.TransformedKey[I * 2 + 1] := (LongInt(KS[1]) shl 24) or (LongInt(KS[3]) shl 16) or
        (LongInt(KS[5]) shl 8) or (LongInt(KS[7]));
    end else begin
      Context.TransformedKey[31 - (I * 2 + 1)] := (LongInt(KS[0]) shl 24) or (LongInt(KS[2]) shl 16) or
        (LongInt(KS[4]) shl 8) or (LongInt(KS[6]));
      Context.TransformedKey[31 - (I * 2)] := (LongInt(KS[1]) shl 24) or (LongInt(KS[3]) shl 16) or
        (LongInt(KS[5]) shl 8) or (LongInt(KS[7]));
    end;
  end;

  Context.Encrypt := Encrypt;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptLBC(const Key : TKey128; var Context : TLBCContext; Rounds: LongInt; Encrypt : Boolean);
type
  TSubKeys = packed record
    case Byte of
      0: (SubKeys64 : array [0..15] of TKey64);
      1: (SubKeysInts : array [0..3, 0..7] of LongInt);
  end;
var
  KeyArray  : pLongIntArray;
  AA, BB    : LongInt;
  CC, DD    : LongInt;
  EE, FF    : LongInt;
  GG, HH    : LongInt;
  I, R      : LongInt;
  Temp      : TSubKeys;
begin
  KeyArray := @Key;
  Context.Encrypt := Encrypt;
  Context.Rounds := Max(4, Min(16, Rounds));


  {fill subkeys by propagating seed}
  for I := 0 to 3 do begin
    {interleave the key with the salt}

    AA := KeyArray^[0]; BB := BCSalts[I];
    CC := KeyArray^[1]; DD := BCSalts[I];
    EE := KeyArray^[2]; FF := BCSalts[I];
    GG := KeyArray^[3]; HH := BCSalts[I];

    {mix all the bits around for 8 rounds}
    {achieves avalanche and eliminates funnels}
    for R := 0 to 7 do begin
      AA := AA xor (BB shl 11); DD := DD + AA; BB := BB + CC;
      BB := BB xor (CC shr 2);  EE := EE + BB; CC := CC + DD;
      CC := CC xor (DD shl 8);  FF := FF + CC; DD := DD + EE;
      DD := DD xor (EE shr 16); GG := GG + DD; EE := EE + FF;
      EE := EE xor (FF shl 10); HH := HH + EE; FF := FF + GG;
      FF := FF xor (GG shr 4);  AA := AA + FF; GG := GG + HH;
      GG := GG xor (HH shl 8);  BB := BB + GG; HH := HH + AA;
      HH := HH xor (AA shr 9);  CC := CC + HH; AA := AA + BB;
    end;

    {assign value to subkey}
    Context.SubKeysInts[I, 0] := AA;
    Context.SubKeysInts[I, 1] := BB;
    Context.SubKeysInts[I, 2] := CC;
    Context.SubKeysInts[I, 3] := DD;
    Context.SubKeysInts[I, 4] := EE;
    Context.SubKeysInts[I, 5] := FF;
    Context.SubKeysInts[I, 6] := GG;
    Context.SubKeysInts[I, 7] := HH;
  end;

  {reverse subkeys if decrypting - easier for EncryptLBC routine}
  if not Encrypt then begin
    for I := 0 to Context.Rounds - 1 do
        Temp.SubKeys64[(Context.Rounds - 1) - I] := Context.SubKeys64[I];
    for I := 0 to Context.Rounds - 1 do
        Context.SubKeys64[I] := Temp.SubKeys64[I];
  end;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptDES(const Context : TDESContext;  var Block : TDESBlock);
const
  SPBox : array [0..7, 0..63] of DWord =                               
    (($01010400, $00000000, $00010000, $01010404, $01010004, $00010404, $00000004, $00010000,
      $00000400, $01010400, $01010404, $00000400, $01000404, $01010004, $01000000, $00000004,
      $00000404, $01000400, $01000400, $00010400, $00010400, $01010000, $01010000, $01000404,
      $00010004, $01000004, $01000004, $00010004, $00000000, $00000404, $00010404, $01000000,
      $00010000, $01010404, $00000004, $01010000, $01010400, $01000000, $01000000, $00000400,
      $01010004, $00010000, $00010400, $01000004, $00000400, $00000004, $01000404, $00010404,
      $01010404, $00010004, $01010000, $01000404, $01000004, $00000404, $00010404, $01010400,
      $00000404, $01000400, $01000400, $00000000, $00010004, $00010400, $00000000, $01010004),
     ($80108020, $80008000, $00008000, $00108020, $00100000, $00000020, $80100020, $80008020,
      $80000020, $80108020, $80108000, $80000000, $80008000, $00100000, $00000020, $80100020,
      $00108000, $00100020, $80008020, $00000000, $80000000, $00008000, $00108020, $80100000,
      $00100020, $80000020, $00000000, $00108000, $00008020, $80108000, $80100000, $00008020,
      $00000000, $00108020, $80100020, $00100000, $80008020, $80100000, $80108000, $00008000,
      $80100000, $80008000, $00000020, $80108020, $00108020, $00000020, $00008000, $80000000,
      $00008020, $80108000, $00100000, $80000020, $00100020, $80008020, $80000020, $00100020,
      $00108000, $00000000, $80008000, $00008020, $80000000, $80100020, $80108020, $00108000),
     ($00000208, $08020200, $00000000, $08020008, $08000200, $00000000, $00020208, $08000200,
      $00020008, $08000008, $08000008, $00020000, $08020208, $00020008, $08020000, $00000208,
      $08000000, $00000008, $08020200, $00000200, $00020200, $08020000, $08020008, $00020208,
      $08000208, $00020200, $00020000, $08000208, $00000008, $08020208, $00000200, $08000000,
      $08020200, $08000000, $00020008, $00000208, $00020000, $08020200, $08000200, $00000000,
      $00000200, $00020008, $08020208, $08000200, $08000008, $00000200, $00000000, $08020008,
      $08000208, $00020000, $08000000, $08020208, $00000008, $00020208, $00020200, $08000008,
      $08020000, $08000208, $00000208, $08020000, $00020208, $00000008, $08020008, $00020200),
     ($00802001, $00002081, $00002081, $00000080, $00802080, $00800081, $00800001, $00002001,
      $00000000, $00802000, $00802000, $00802081, $00000081, $00000000, $00800080, $00800001,
      $00000001, $00002000, $00800000, $00802001, $00000080, $00800000, $00002001, $00002080,
      $00800081, $00000001, $00002080, $00800080, $00002000, $00802080, $00802081, $00000081,
      $00800080, $00800001, $00802000, $00802081, $00000081, $00000000, $00000000, $00802000,
      $00002080, $00800080, $00800081, $00000001, $00802001, $00002081, $00002081, $00000080,
      $00802081, $00000081, $00000001, $00002000, $00800001, $00002001, $00802080, $00800081,
      $00002001, $00002080, $00800000, $00802001, $00000080, $00800000, $00002000, $00802080),
     ($00000100, $02080100, $02080000, $42000100, $00080000, $00000100, $40000000, $02080000,
      $40080100, $00080000, $02000100, $40080100, $42000100, $42080000, $00080100, $40000000,
      $02000000, $40080000, $40080000, $00000000, $40000100, $42080100, $42080100, $02000100,
      $42080000, $40000100, $00000000, $42000000, $02080100, $02000000, $42000000, $00080100,
      $00080000, $42000100, $00000100, $02000000, $40000000, $02080000, $42000100, $40080100,
      $02000100, $40000000, $42080000, $02080100, $40080100, $00000100, $02000000, $42080000,
      $42080100, $00080100, $42000000, $42080100, $02080000, $00000000, $40080000, $42000000,
      $00080100, $02000100, $40000100, $00080000, $00000000, $40080000, $02080100, $40000100),
     ($20000010, $20400000, $00004000, $20404010, $20400000, $00000010, $20404010, $00400000,
      $20004000, $00404010, $00400000, $20000010, $00400010, $20004000, $20000000, $00004010,
      $00000000, $00400010, $20004010, $00004000, $00404000, $20004010, $00000010, $20400010,
      $20400010, $00000000, $00404010, $20404000, $00004010, $00404000, $20404000, $20000000,
      $20004000, $00000010, $20400010, $00404000, $20404010, $00400000, $00004010, $20000010,
      $00400000, $20004000, $20000000, $00004010, $20000010, $20404010, $00404000, $20400000,
      $00404010, $20404000, $00000000, $20400010, $00000010, $00004000, $20400000, $00404010,
      $00004000, $00400010, $20004010, $00000000, $20404000, $20000000, $00400010, $20004010),
     ($00200000, $04200002, $04000802, $00000000, $00000800, $04000802, $00200802, $04200800,
      $04200802, $00200000, $00000000, $04000002, $00000002, $04000000, $04200002, $00000802,
      $04000800, $00200802, $00200002, $04000800, $04000002, $04200000, $04200800, $00200002,
      $04200000, $00000800, $00000802, $04200802, $00200800, $00000002, $04000000, $00200800,
      $04000000, $00200800, $00200000, $04000802, $04000802, $04200002, $04200002, $00000002,
      $00200002, $04000000, $04000800, $00200000, $04200800, $00000802, $00200802, $04200800,
      $00000802, $04000002, $04200802, $04200000, $00200800, $00000000, $00000002, $04200802,
      $00000000, $00200802, $04200000, $00000800, $04000002, $04000800, $00000800, $00200002),
     ($10001040, $00001000, $00040000, $10041040, $10000000, $10001040, $00000040, $10000000,
      $00040040, $10040000, $10041040, $00041000, $10041000, $00041040, $00001000, $00000040,
      $10040000, $10000040, $10001000, $00001040, $00041000, $00040040, $10040040, $10041000,
      $00001040, $00000000, $00000000, $10040040, $10000040, $10001000, $00041040, $00040000,
      $00041040, $00040000, $10041000, $00001000, $00000040, $10040040, $00001000, $00041040,
      $10001000, $00000040, $10000040, $10040000, $10040040, $10000000, $00040000, $10001040,
      $00000000, $10041040, $00040040, $10000040, $10040000, $10001000, $10001040, $00000000,
      $10041040, $00041000, $00041000, $00001040, $00001040, $00040040, $10000000, $10041000));
var
  I, L, R, Work : DWord;
  CPtr          : PDWord;

  procedure SplitBlock(const Block : TDESBlock;  var L, R : DWord); register;
  asm
    push ebx
    push eax
    mov  eax, [eax]
    mov  bh, al
    mov  bl, ah
    rol  ebx, 16
    shr  eax, 16
    mov  bh, al
    mov  bl, ah
    mov  [edx], ebx
    pop  eax
    mov  eax, [eax+4]
    mov  bh, al
    mov  bl, ah
    rol  ebx, 16
    shr  eax, 16
    mov  bh, al
    mov  bl, ah
    mov  [ecx], ebx
    pop  ebx
  end;

  procedure JoinBlock(const L, R : LongInt;  var Block : TDESBlock); register;
  asm
    push ebx
    mov  bh, al
    mov  bl, ah
    rol  ebx, 16
    shr  eax, 16
    mov  bh, al
    mov  bl, ah
    mov  [ecx+4], ebx
    mov  bh, dl
    mov  bl, dh
    rol  ebx, 16
    shr  edx, 16
    mov  bh, dl
    mov  bl, dh
    mov  [ecx], ebx
    pop  ebx
  end;

  procedure IPerm(var L, R : DWord);                                   
  var
    Work : DWord;                                                      
  begin
    Work := ((L shr 4) xor R) and $0F0F0F0F;
    R := R xor Work;
    L := L xor Work shl 4;

    Work := ((L shr 16) xor R) and $0000FFFF;
    R := R xor Work;
    L := L xor Work shl 16;

    Work := ((R shr 2) xor L) and $33333333;
    L := L xor Work;
    R := R xor Work shl 2;

    Work := ((R shr 8) xor L) and $00FF00FF;
    L := L xor Work;
    R := R xor Work shl 8;

    R := (R shl 1) or (R shr 31);
    Work := (L xor R) and $AAAAAAAA;
    L := L xor Work;
    R := R xor Work;
    L := (L shl 1) or (L shr 31);
  end;

  procedure FPerm(var L, R : DWord);                                   
  var
    Work : DWord;                                                      
  begin
    L := L;

    R := (R shl 31) or (R shr 1);
    Work := (L xor R) and $AAAAAAAA;
    L := L xor Work;
    R := R xor Work;
    L := (L shr 1) or (L shl 31);

    Work := ((L shr 8) xor R) and $00FF00FF;
    R := R xor Work;
    L := L xor Work shl 8;

    Work := ((L shr 2) xor R) and $33333333;
    R := R xor Work;
    L := L xor Work shl 2;

    Work := ((R shr 16) xor L) and $0000FFFF;
    L := L xor Work;
    R := R xor Work shl 16;

    Work := ((R shr 4) xor L) and $0F0F0F0F;
    L := L xor Work;
    R := R xor Work shl 4;
  end;

begin
  SplitBlock(Block, L, R);
  IPerm(L, R);

  CPtr := @Context;
  for I := 0 to 7 do begin
    Work := (((R shr 4) or (R shl 28)) xor CPtr^);
    Inc(CPtr);
    L := L xor SPBox[6, Work and $3F];
    L := L xor SPBox[4, Work shr 8 and $3F];
    L := L xor SPBox[2, Work shr 16 and $3F];
    L := L xor SPBox[0, Work shr 24 and $3F];

    Work := (R xor CPtr^);
    Inc(CPtr);
    L := L xor SPBox[7, Work and $3F];
    L := L xor SPBox[5, Work shr 8 and $3F];
    L := L xor SPBox[3, Work shr 16 and $3F];
    L := L xor SPBox[1, Work shr 24 and $3F];

    Work := (((L shr 4) or (L shl 28)) xor CPtr^);
    Inc(CPtr);
    R := R xor SPBox[6, Work and $3F];
    R := R xor SPBox[4, Work shr 8 and $3F];
    R := R xor SPBox[2, Work shr 16 and $3F];
    R := R xor SPBox[0, Work shr 24 and $3F];

    Work := (L xor CPtr^);
    Inc(CPtr);
    R := R xor SPBox[7, Work and $3F];
    R := R xor SPBox[5, Work shr 8 and $3F];
    R := R xor SPBox[3, Work shr 16 and $3F];
    R := R xor SPBox[1, Work shr 24 and $3F];
  end;

  FPerm(L, R);
  JoinBlock(L, R, Block);
end;
{ -------------------------------------------------------------------------- }
procedure EncryptDESCBC(const Context : TDESContext;  const Prev : TDESBlock;  var Block : TDESBlock);
begin
  if Context.Encrypt then begin
    XorMem(Block, Prev, SizeOf(Block));
    EncryptDES(Context, Block);
  end else begin
    EncryptDES(Context, Block);
    XorMem(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptTripleDES(const Key : TKey128;  var Context : TTripleDESContext; Encrypt : Boolean);
var
  KeyArray : array [0..1] of TKey64;
begin
  Move(Key, KeyArray, SizeOf(KeyArray));                             {!!.01}
  if Encrypt then begin
    InitEncryptDES(KeyArray[0], Context[0], True);
    InitEncryptDES(KeyArray[1], Context[1], False);
  end else begin
    InitEncryptDES(KeyArray[0], Context[0], False);
    InitEncryptDES(KeyArray[1], Context[1], True);
  end;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptTripleDES(const Context : TTripleDESContext;  var Block : TDESBlock);
begin
  EncryptDES(Context[0], Block);
  EncryptDES(Context[1], Block);
  EncryptDES(Context[0], Block);
end;
{ -------------------------------------------------------------------------- }
procedure EncryptTripleDESCBC(const Context : TTripleDESContext;  const Prev : TDESBlock; var Block : TDESBlock);
begin
  if Context[0].Encrypt then begin
    XorMem(Block, Prev, SizeOf(Block));
    EncryptDES(Context[0], Block);
    EncryptDES(Context[1], Block);
    EncryptDES(Context[0], Block);
  end else begin
    EncryptDES(Context[0], Block);
    EncryptDES(Context[1], Block);
    EncryptDES(Context[0], Block);
    XorMem(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
{!!.01}
procedure InitEncryptTripleDES3Key(const Key1, Key2, Key3 : TKey64;
            var Context : TTripleDESContext3Key; Encrypt : Boolean);
begin
  if Encrypt then begin
    InitEncryptDES(Key1, Context[0], True);
    InitEncryptDES(Key2, Context[1], False);
    InitEncryptDES(Key3, Context[2], True);
  end else begin
    InitEncryptDES(Key1, Context[2], False);
    InitEncryptDES(Key2, Context[1], True);
    InitEncryptDES(Key3, Context[0], False);
  end;
end;
{ -------------------------------------------------------------------------- }
{!!.01}
procedure EncryptTripleDES3Key(const Context : TTripleDESContext3Key;
            var Block : TDESBlock);
begin
  EncryptDES(Context[2], Block);
  EncryptDES(Context[1], Block);
  EncryptDES(Context[0], Block);
end;
{ -------------------------------------------------------------------------- }
{!!.01}
procedure EncryptTripleDESCBC3Key(const Context : TTripleDESContext3Key;
            const Prev : TDESBlock; var Block : TDESBlock);
begin
  if Context[0].Encrypt then begin
    XorMem(Block, Prev, SizeOf(Block));
    EncryptDES(Context[0], Block);
    EncryptDES(Context[1], Block);
    EncryptDES(Context[2], Block);
  end else begin
    EncryptDES(Context[0], Block);
    EncryptDES(Context[1], Block);
    EncryptDES(Context[2], Block);
    XorMem(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptLQC(const Key : TKey128; var Block : TLQCBlock; Encrypt : Boolean);
const
  CKeyBox : array [False..True, 0..3, 0..2] of LongInt =
    (((0, 3, 1), (2, 1, 3), (1, 0, 2), (3, 2, 0)),
     ((3, 2, 0), (1, 0, 2), (2, 1, 3), (0, 3, 1)));
var
  KeyInts : array [0..3] of Longint;                                 {!!.01}
  Blocks  : array [0..1] of Longint;                                 {!!.01}
  Work    : LongInt;
  Right   : LongInt;
  Left    : LongInt;
  R       : LongInt;
  AA, BB  : LongInt;
  CC, DD  : LongInt;
begin
  Move(Key, KeyInts, SizeOf(KeyInts));                               {!!.01}
  Move(Block, Blocks, SizeOf(Blocks));                               {!!.01}
  Right := Blocks[0];
  Left := Blocks[1];

  for R := 0 to 3 do begin
    {transform the right side}
    AA := Right;
    BB := KeyInts[CKeyBox[Encrypt, R, 0]];
    CC := KeyInts[CKeyBox[Encrypt, R, 1]];
    DD := KeyInts[CKeyBox[Encrypt, R, 2]];

    {commented code does not affect results - removed for speed}
    AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 7);
    BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 13);
    CC := CC + BB; BB := BB + CC; CC := CC xor (CC shr 17);
    DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 9);
    AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 3);
    BB := BB + AA; {AA := AA + BB;}  BB := BB xor (BB shl 7);
    CC := CC + BB; {BB := BB + CC;}  CC := CC xor (DD shr 15);
    DD := DD + CC; {CC := CC + DD;}  DD := DD xor (DD shl 11);

    Work := Left xor DD;
    Left := Right;
    Right := Work;
  end;

  Blocks[0] := Left;
  Blocks[1] := Right;
  Move(Blocks, Block, SizeOf(Block));                                {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure EncryptLQCCBC(const Key : TKey128; const Prev : TLQCBlock; var Block : TLQCBlock; Encrypt : Boolean);
begin
  if Encrypt then begin
    XorMem(Block, Prev, SizeOf(Block));
    EncryptLQC(Key, Block, Encrypt);
  end else begin
    EncryptLQC(Key, Block, Encrypt);
    XorMem(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptBF(Key : TKey128; var Context : TBFContext);
var
  I     : Integer;
  J     : Integer;
  K     : Integer;
  Data  : LongInt;
  Block : TBFBlock;
begin
  {initialize PArray}
  Move(bf_P, Context.PBox, SizeOf(Context.PBox));
  {initialize SBox}
  Move(bf_S, Context.SBox, SizeOf(Context.SBox));

  {update PArray with the key bits}
  J := 0;
  for I := 0 to (BFRounds+1) do begin
    Data := 0;
    for K := 0 to 3 do begin
      Data := (Data shl 8) or Key[J];
      Inc(J);
      if J >= SizeOf(Key) then
        J := 0;
    end;
    Context.PBox[I] := Context.PBox[I] xor Data;
  end;

  {encrypt an all-zero string using the Blowfish algorithm and}
  {replace the elements of the P-array with the output of this process}

  Block[0] := 0;
  Block[1] := 0;
  I := 0;
  repeat
    EncryptBF(Context, Block, True);
    Context.PBox[I] := Block[0];
    Context.PBox[I+1] := Block[1];
    Inc(I, 2);
  until I > BFRounds+1;

  {continue the process, replacing the elements of the four S-boxes in}
  {order, with the output of the continuously changing Blowfish algorithm}

  for J := 0 to 3 do begin
    I := 0;
    repeat
      EncryptBF(Context, Block, True);
      Context.SBox[J, I] := Block[0];
      Context.SBox[J, I+1] := Block[1];
      Inc(I, 2);
    until I > 255;
  end;

  {in total, 521 iterations are required to generate all required subkeys. }
end;
{ -------------------------------------------------------------------------- }
procedure EncryptBF(const Context : TBFContext;
  var Block : TBFBlock; Encrypt : Boolean);
var
  I : Integer;
  TmpBlock : TBFBlockEx;                                             {!!.01}
begin
  Move(Block, TmpBlock, SizeOf(TmpBlock));                           {!!.01}
  if Encrypt then begin
    Block[0] := Block[0] xor Context.PBox[0];

    {16 Rounds to go (8 double rounds to avoid swaps)}
    I := 1;
    repeat
      {first half round }
      Block[1] := Block[1] xor Context.PBox[I] xor (((
                  Context.SBox[0, TmpBlock.Xl[3]] + Context.SBox[1, TmpBlock.Xl[2]])
                  xor Context.SBox[2, TmpBlock.Xl[1]]) + Context.SBox[3, TmpBlock.Xl[0]]);
      {second half round }
      Block[0] := Block[0] xor Context.PBox[I+1] xor (((
                  Context.SBox[0, TmpBlock.Xr[3]] + Context.SBox[1, TmpBlock.Xr[2]])
                  xor Context.SBox[2, TmpBlock.Xr[1]]) + Context.SBox[3, TmpBlock.Xr[0]]);
      Inc(I, 2);
    until I > BFRounds;
    Block[1] := Block[1] xor Context.PBox[(BFRounds+1)];
  end else begin
    Block[1] := Block[1] xor Context.PBox[(BFRounds+1)];

    {16 Rounds to go (8 double rounds to avoid swaps)}
    I := BFRounds;
    repeat
      {first half round }
      Block[0] := Block[0] xor Context.PBox[I] xor (((
                  Context.SBox[0, TmpBlock.Xr[3]] + Context.SBox[1, TmpBlock.Xr[2]])
                  xor Context.SBox[2, TmpBlock.Xr[1]]) + Context.SBox[3, TmpBlock.Xr[0]]);
      {second half round }
      Block[1] := Block[1] xor Context.PBox[i-1] xor (((
                  Context.SBox[0, TmpBlock.Xl[3]] + Context.SBox[1, TmpBlock.Xl[2]])
                  xor Context.SBox[2, TmpBlock.Xl[1]]) + Context.SBox[3, TmpBlock.Xl[0]]);
       Dec (I, 2);
     until I < 1;
     Block[0] := Block[0] xor Context.PBox[0];
  end;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptBFCBC(const Context : TBFContext; const Prev : TBFBlock;
  var Block : TBFBlock; Encrypt : Boolean);
begin
  if Encrypt then begin
    XorMem(Block, Prev, SizeOf(Block));
    EncryptBF(Context, Block, Encrypt);
  end else begin
    EncryptBF(Context, Block, Encrypt);
    XorMem(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptLSC(const Key; KeySize : Integer; var Context : TLSCContext);
var
  R, I, A   : LongInt;
  X         : Byte;
begin
  {initialize SBox}
  for I := 0 to 255 do
    Context.SBox[I] := I;

  A := 0;
  for R := 0 to 2 do  {3 rounds - "A" accumulates}
    for I := 0 to 255 do begin
      A := A + Context.SBox[I] + TByteArray(Key)[I mod KeySize];     {!!.01}
      X := Context.SBox[I];
      Context.SBox[I] := Context.SBox[Byte(A)];
      Context.SBox[Byte(A)] := X;
    end;

  Context.Index := 0;
  Context.Accumulator := A;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptLSC(var Context : TLSCContext; var Buf; BufSize : LongInt);
var
  L, Y, X   : LongInt;
  I, A      : LongInt;
begin
  I := Context.Index;
  A := Context.Accumulator;

  for L := 0 to BufSize - 1 do begin
    I := I + 1;

    X := Context.SBox[Byte(I)];
    Y := Context.SBox[Byte(X)] + X;
    Context.SBox[Byte(I)] := Context.SBox[Byte(Y)];
    Context.SBox[Byte(Y)] := X;

    A := A + Context.SBox[Byte(Byte(Y shr 8) + Byte(Y))];
    TByteArray(Buf)[L] := TByteArray(Buf)[L] xor Byte(A);            {!!.01}
  end;

  Context.Index := I;
  Context.Accumulator := A;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptRNG32(Key : LongInt; var Context : TRNG32Context);
begin
  LongInt(Context) := Key;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptRNG32(var Context : TRNG32Context; var Buf; BufSize : LongInt);
var
  I     : LongInt;
begin
  for I := 0 to BufSize - 1 do
    TByteArray(Buf)[I] := TByteArray(Buf)[I] xor                     {!!.01}
                            Random32Byte(LongInt(Context));
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptRNG64(KeyHi, KeyLo : LongInt; var Context : TRNG64Context);
begin
  TInt64(Context).Lo := KeyLo;
  TInt64(Context).Hi := KeyHi;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptRNG64(var Context : TRNG64Context; var Buf; BufSize : LongInt);
var
  I : Integer;
begin
  for I := 0 to BufSize - 1 do
    TByteArray(Buf)[I] := TByteArray(Buf)[I] xor                     {!!.01}
                            Random64Byte(TInt64(Context));
end;
{ -------------------------------------------------------------------------- }
procedure GenerateRandomKey(var Key; KeySize : Integer);
var
  I     : Integer;
begin
  Randomize;
  for I := 0 to KeySize - 1 do
    TByteArray(Key)[I] := System.Random(256);                        {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure GenerateLMDKey(var Key; KeySize : Integer;
            const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  GenerateLMDKeyW(Key, KeySize, Str);
  {$ELSE}
  GenerateLMDKeyA(Key, KeySize, Str);
  {$ENDIF}
end;

procedure GenerateLMDKeyA(var Key; KeySize : Integer;
            const Str : Ansistring);
begin
  HashLMD(Key, KeySize, Str[1], Length(Str) * SizeOf(AnsiChar));
end;

{$IFDEF UNICODE}
procedure GenerateLMDKeyW(var Key; KeySize : Integer; const Str : UnicodeString);
begin
  HashLMD(Key, KeySize, Str[1], Length(Str) * SizeOf(WideChar));
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure GenerateMD5Key(var Key : TKey128; const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  GenerateMD5KeyW(Key, Str);
  {$ELSE}
  GenerateMD5KeyA(Key, Str);
  {$ENDIF}
end;

procedure GenerateMD5KeyA(var Key : TKey128; const Str : AnsiString);
var
  D : TMD5Digest;
begin
  HashMD5(D, Str[1], Length(Str) * SizeOf(AnsiChar));
  Key := TKey128(D);
end;

{$IFDEF UNICODE}
procedure GenerateMD5KeyW(var Key : TKey128; const Str : UnicodeString);
var
  D : TMD5Digest;
begin
  HashMD5(D, Str[1], Length(Str) * SizeOf(WideChar));
  Key := TKey128(D);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
function Ran0Prim(var Seed : LongInt; IA, IQ, IR : LongInt) : LongInt;
const
  IM = 2147483647;
  MA = 123459876;
var
  I, K : LongInt;
begin
  {XORing with mask avoids seeds of zero}
  I := Seed xor MA;
  K := I div IQ;
  I := (IA * (I - (K * IQ))) - (IR * K);
  if I < 0 then
    I := I + IM;
  Result := I xor MA;
  Seed := Result;
end;
{ -------------------------------------------------------------------------- }
function Ran01(var Seed : LongInt) : LongInt;
begin
  Result := Ran0Prim(Seed, 16807, 127773, 2836);
end;
{ -------------------------------------------------------------------------- }
function Ran02(var Seed : LongInt) : LongInt;
begin
  Result := Ran0Prim(Seed, 48271, 44488, 3399);
end;
{ -------------------------------------------------------------------------- }
function Ran03(var Seed : LongInt) : LongInt;
begin
  Result := Ran0Prim(Seed, 69621, 30845, 23902);
end;
{ -------------------------------------------------------------------------- }
function Random32Byte(var Seed : LongInt) : Byte;
var
  L : LongInt;
  R : TLongIntRec;
begin
  L := Ran01(Seed);
  R := TLongIntRec(L);
  Result := R.LoLo xor R.LoHi xor R.HiLo xor R.HiHi;
end;
{ -------------------------------------------------------------------------- }
function Random64(var Seed : TInt64) : LongInt;
begin
  Ran01(Seed.Lo);
  Ran01(Seed.Hi);
  Result := Seed.Lo xor Seed.Hi;
end;
{ -------------------------------------------------------------------------- }
function Random64Byte(var Seed : TInt64) : Byte;
var
  L : LongInt;
  R : TLongIntRec;
begin
  L := Random64(Seed);
  R := TLongIntRec(L);
  Result := R.LoLo xor R.LoHi xor R.HiLo xor R.HiHi;
end;
{ -------------------------------------------------------------------------- }
procedure  ShrinkDESKey(var Key : TKey64);
const
  SK1 : TKey64 = ($C4,$08,$B0,$54,$0B,$A1,$E0,$AE);
  SK2 : TKey64 = ($EF,$2C,$04,$1C,$E6,$38,$2F,$E6);
var
  I       : Integer;
  Work1   : TKey64;
  Work2   : TKey64;
  Context : TDESContext;
begin
  {step #1 zero the parity bits - 8, 16, 24, ..., 64}
  for I := 0 to 7 do
    Work1[I] := Key[I] and $FE;

  {step #2 encrypt output of #1 with SK1 and xor with output of #1}
  InitEncryptDES(SK1, Context, True);
  Work2 := Work1; {make copy}
  EncryptDES(Context, TDESBlock(Work2));
  for I := 0 to 7 do
    Work1[I] := Work1[I] xor Work2[I];

  {step #3 zero bits 1,2,3,4,8,16,17,18,19,20,24,32,33,34,35,36,40,48,49,50,51,52,56,64}
  TInt64(Work1).Lo := TInt64(Work1).Lo and $F101F101;
  TInt64(Work1).Hi := TInt64(Work1).Hi and $F101F101;

  {step #4 encrypt output of #3 with SK2}
  InitEncryptDES(SK2, Context, True);
  EncryptDES(Context, TDESBlock(Work1));

  Key := Work1;
end;
{ -------------------------------------------------------------------------- }
procedure Mix128(var X : T128Bit);
var
  AA, BB, CC, DD : LongInt;
begin
  AA := X[0];  BB := X[1];  CC := X[2];  DD := X[3];

  AA := AA + DD;  DD := DD + AA;  AA := AA xor (AA shr 7);
  BB := BB + AA;  AA := AA + BB;  BB := BB xor (BB shl 13);
  CC := CC + BB;  BB := BB + CC;  CC := CC xor (CC shr 17);
  DD := DD + CC;  CC := CC + DD;  DD := DD xor (DD shl 9);
  AA := AA + DD;  DD := DD + AA;  AA := AA xor (AA shr 3);
  BB := BB + AA;  AA := AA + BB;  BB := BB xor (BB shl 7);
  CC := CC + BB;  BB := BB + CC;  CC := CC xor (DD shr 15);
  DD := DD + CC;  CC := CC + DD;  DD := DD xor (DD shl 11);

  X[0] := AA;  X[1] := BB;  X[2] := CC;  X[3] := DD;
end;
{ -------------------------------------------------------------------------- }
procedure HashELF(var Digest : LongInt; const Buf;  BufSize : LongInt);
var
  I, X  : LongInt;
begin
  Digest := 0;
  for I := 0 to BufSize - 1 do begin
    Digest := (Digest shl 4) + TByteArray(Buf)[I];                   {!!.01}
    X := Digest and $F0000000;
    if (X <> 0) then
      Digest := Digest xor (X shr 24);
    Digest := Digest and (not X);
  end;
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure StringHashELFW(var Digest : LongInt; const Str : UnicodeString);
begin
  HashELF(Digest, Str[1], Length(Str) * SizeOf(WideChar));
end;
{$ENDIF}

procedure StringHashELFA(var Digest : LongInt; const Str : AnsiString);
begin
  HashELF(Digest, Str[1], Length(Str) * SizeOf(AnsiChar));
end;
{ -------------------------------------------------------------------------- }
function RolX(I, C : DWord) : DWord; register;
asm
  mov  ecx, edx         {get count to cl}
  rol  eax, cl          {rotate eax by cl}
end;
{ -------------------------------------------------------------------------- }
procedure Transform(var Buffer : array of DWord;  const InBuf : array of DWord);
const
  S11 = 7;
  S12 = 12;
  S13 = 17;
  S14 = 22;
  S21 = 5;
  S22 = 9;
  S23 = 14;
  S24 = 20;
  S31 = 4;
  S32 = 11;
  S33 = 16;
  S34 = 23;
  S41 = 6;
  S42 = 10;
  S43 = 15;
  S44 = 21;
var
  Buf : array [0..3] of DWord;                                       {!!.01}
  InA : array [0..15] of DWord;                                      {!!.01}
var
  A   : DWord;
  B   : DWord;
  C   : DWord;
  D   : DWord;

  procedure FF(var A : DWord;  B, C, D, X, S, AC : DWord);
  begin
    A := RolX(A + ((B and C) or (not B and D)) + X + AC, S) + B;
  end;

  procedure GG(var A : DWord;  B, C, D, X, S, AC : DWord);
  begin
    A := RolX(A + ((B and D) or (C and not D)) + X + AC, S) + B;
  end;

  procedure HH(var A : DWord;  B, C, D, X, S, AC : DWord);
  begin
    A := RolX(A + (B xor C xor D) + X + AC, S) + B;
  end;

  procedure II(var A : DWord;  B, C, D, X, S, AC : DWord);
  begin
    A := RolX(A + (C xor (B or not D)) + X + AC, S) + B;
  end;

begin
  Move(Buffer, Buf, SizeOf(Buf));                                    {!!.01}
  Move(InBuf, InA, SizeOf(InA));                                     {!!.01}
  A := Buf [0];
  B := Buf [1];
  C := Buf [2];
  D := Buf [3];


  {round 1}
  FF(A, B, C, D, InA [ 0], S11, $D76AA478);  { 1 }
  FF(D, A, B, C, InA [ 1], S12, $E8C7B756);  { 2 }
  FF(C, D, A, B, InA [ 2], S13, $242070DB);  { 3 }
  FF(B, C, D, A, InA [ 3], S14, $C1BDCEEE);  { 4 }
  FF(A, B, C, D, InA [ 4], S11, $F57C0FAF);  { 5 }
  FF(D, A, B, C, InA [ 5], S12, $4787C62A);  { 6 }
  FF(C, D, A, B, InA [ 6], S13, $A8304613);  { 7 }
  FF(B, C, D, A, InA [ 7], S14, $FD469501);  { 8 }
  FF(A, B, C, D, InA [ 8], S11, $698098D8);  { 9 }
  FF(D, A, B, C, InA [ 9], S12, $8B44F7AF);  { 10 }
  FF(C, D, A, B, InA [10], S13, $FFFF5BB1);  { 11 }
  FF(B, C, D, A, InA [11], S14, $895CD7BE);  { 12 }
  FF(A, B, C, D, InA [12], S11, $6B901122);  { 13 }
  FF(D, A, B, C, InA [13], S12, $FD987193);  { 14 }
  FF(C, D, A, B, InA [14], S13, $A679438E);  { 15 }
  FF(B, C, D, A, InA [15], S14, $49B40821);  { 16 }

  {round 2}
  GG(A, B, C, D, InA [ 1], S21, $F61E2562);  { 17 }
  GG(D, A, B, C, InA [ 6], S22, $C040B340);  { 18 }
  GG(C, D, A, B, InA [11], S23, $265E5A51);  { 19 }
  GG(B, C, D, A, InA [ 0], S24, $E9B6C7AA);  { 20 }
  GG(A, B, C, D, InA [ 5], S21, $D62F105D);  { 21 }
  GG(D, A, B, C, InA [10], S22, $02441453);  { 22 }
  GG(C, D, A, B, InA [15], S23, $D8A1E681);  { 23 }
  GG(B, C, D, A, InA [ 4], S24, $E7D3FBC8);  { 24 }
  GG(A, B, C, D, InA [ 9], S21, $21E1CDE6);  { 25 }
  GG(D, A, B, C, InA [14], S22, $C33707D6);  { 26 }
  GG(C, D, A, B, InA [ 3], S23, $F4D50D87);  { 27 }
  GG(B, C, D, A, InA [ 8], S24, $455A14ED);  { 28 }
  GG(A, B, C, D, InA [13], S21, $A9E3E905);  { 29 }
  GG(D, A, B, C, InA [ 2], S22, $FCEFA3F8);  { 30 }
  GG(C, D, A, B, InA [ 7], S23, $676F02D9);  { 31 }
  GG(B, C, D, A, InA [12], S24, $8D2A4C8A);  { 32 }

  {round 3}
  HH(A, B, C, D, InA [ 5], S31, $FFFA3942);  { 33 }
  HH(D, A, B, C, InA [ 8], S32, $8771F681);  { 34 }
  HH(C, D, A, B, InA [11], S33, $6D9D6122);  { 35 }
  HH(B, C, D, A, InA [14], S34, $FDE5380C);  { 36 }
  HH(A, B, C, D, InA [ 1], S31, $A4BEEA44);  { 37 }
  HH(D, A, B, C, InA [ 4], S32, $4BDECFA9);  { 38 }
  HH(C, D, A, B, InA [ 7], S33, $F6BB4B60);  { 39 }
  HH(B, C, D, A, InA [10], S34, $BEBFBC70);  { 40 }
  HH(A, B, C, D, InA [13], S31, $289B7EC6);  { 41 }
  HH(D, A, B, C, InA [ 0], S32, $EAA127FA);  { 42 }
  HH(C, D, A, B, InA [ 3], S33, $D4EF3085);  { 43 }
  HH(B, C, D, A, InA [ 6], S34,  $4881D05);  { 44 }
  HH(A, B, C, D, InA [ 9], S31, $D9D4D039);  { 45 }
  HH(D, A, B, C, InA [12], S32, $E6DB99E5);  { 46 }
  HH(C, D, A, B, InA [15], S33, $1FA27CF8);  { 47 }
  HH(B, C, D, A, InA [ 2], S34, $C4AC5665);  { 48 }

  {round 4}
  II(A, B, C, D, InA [ 0], S41, $F4292244);  { 49 }
  II(D, A, B, C, InA [ 7], S42, $432AFF97);  { 50 }
  II(C, D, A, B, InA [14], S43, $AB9423A7);  { 51 }
  II(B, C, D, A, InA [ 5], S44, $FC93A039);  { 52 }
  II(A, B, C, D, InA [12], S41, $655B59C3);  { 53 }
  II(D, A, B, C, InA [ 3], S42, $8F0CCC92);  { 54 }
  II(C, D, A, B, InA [10], S43, $FFEFF47D);  { 55 }
  II(B, C, D, A, InA [ 1], S44, $85845DD1);  { 56 }
  II(A, B, C, D, InA [ 8], S41, $6FA87E4F);  { 57 }
  II(D, A, B, C, InA [15], S42, $FE2CE6E0);  { 58 }
  II(C, D, A, B, InA [ 6], S43, $A3014314);  { 59 }
  II(B, C, D, A, InA [13], S44, $4E0811A1);  { 60 }
  II(A, B, C, D, InA [ 4], S41, $F7537E82);  { 61 }
  II(D, A, B, C, InA [11], S42, $BD3AF235);  { 62 }
  II(C, D, A, B, InA [ 2], S43, $2AD7D2BB);  { 63 }
  II(B, C, D, A, InA [ 9], S44, $EB86D391);  { 64 }

  Inc(Buf [0], A);
  Inc(Buf [1], B);
  Inc(Buf [2], C);
  Inc(Buf [3], D);

  Move(Buf, Buffer, SizeOf(Buffer));                                 {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure InitMD5(var Context : TMD5Context);
var
  MD5 : TMD5ContextEx;                                               {!!.01}
begin
  Move(Context, MD5, SizeOf(MD5));                                   {!!.01}
  MD5.Count[0] := 0;
  MD5.Count[1] := 0;

  {load magic initialization constants}
  MD5.State[0] := $67452301;
  MD5.State[1] := $EFCDAB89;
  MD5.State[2] := $98BADCFE;
  MD5.State[3] := $10325476;
  Move(MD5, Context, SizeOf(Context));                               {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure UpdateMD5(var Context : TMD5Context;  const Buf;  BufSize : LongInt);
var
  MD5    : TMD5ContextEx;
  InBuf  : array [0..15] of DWord;
  BufOfs : LongInt;
  MDI    : Word;
  I      : Word;
  II     : Word;
begin
  Move(Context, MD5, SizeOf(MD5));                                   {!!.01}

  {compute number of bytes mod 64}
  MDI := (MD5.Count[0] shr 3) and $3F;

  {update number of bits}
  if ((MD5.Count[0] + (DWord(BufSize) shl 3)) < MD5.Count[0]) then
    Inc(MD5.Count[1]);
  Inc(MD5.Count[0], BufSize shl 3);
  Inc(MD5.Count[1], BufSize shr 29);

  {add new byte acters to buffer}
  BufOfs := 0;
  while (BufSize > 0) do begin
    Dec(BufSize);
    MD5.Buf[MDI] := TByteArray(Buf)[BufOfs];                         {!!.01}
    Inc(MDI);
    Inc(BufOfs);
    if (MDI = $40) then begin
      II := 0;
      for I := 0 to 15 do begin
        InBuf[I] := LongInt(MD5.Buf[II + 3]) shl 24 or
          LongInt(MD5.Buf[II + 2]) shl 16 or
          LongInt(MD5.Buf[II + 1]) shl 8 or
          LongInt(MD5.Buf[II]);
        Inc(II, 4);
      end;
      Transform(MD5.State, InBuf);
      Transform(TMD5ContextEx( Context ).State, InBuf);
      MDI := 0;
    end;
  end;
  Move(MD5, Context, SizeOf(Context));                               {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure FinalizeMD5(var Context : TMD5Context; var Digest : TMD5Digest);
const
  Padding: array [0..63] of Byte = (
    $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00);
var
  MD5    : TMD5ContextEx;
  InBuf  : array [0..15] of DWord;
  MDI    : LongInt;
  I      : Word;
  II     : Word;
  PadLen : Word;
begin
  Move(Context, MD5, SizeOf(MD5));                                   {!!.01}
  {save number of bits}
  InBuf[14] := MD5.Count[0];
  InBuf[15] := MD5.Count[1];
  {compute number of bytes mod 64}
  MDI := (MD5.Count[0] shr 3) and $3F;
  {pad out to 56 mod 64}
  if (MDI < 56) then
    PadLen := 56 - MDI
  else
    PadLen := 120 - MDI;
  UpdateMD5(Context, Padding, PadLen);

  Move(Context, MD5, SizeOf(MD5));                                   {!!.01}

  {append length in bits and transform}
  II := 0;
  for I := 0 to 13 do begin
    InBuf[I] :=
      ( LongInt( MD5.Buf[ II + 3 ]) shl 24 ) or
      ( LongInt( MD5.Buf[ II + 2 ]) shl 16 ) or
      ( LongInt( MD5.Buf[ II + 1 ]) shl 8  ) or
        LongInt( MD5.Buf[ II     ]);
    Inc(II, 4);
  end;
  Transform(MD5.State, InBuf);
  {store buffer in digest}
  II := 0;
  for I := 0 to 3 do begin
    Digest[II] := Byte(MD5.State[I] and $FF);
    Digest[II + 1] := Byte((MD5.State[I] shr 8) and $FF);
    Digest[II + 2] := Byte((MD5.State[I] shr 16) and $FF);
    Digest[II + 3] := Byte((MD5.State[I] shr 24) and $FF);
    Inc(II, 4);
  end;
  Move(MD5, Context, SizeOf(Context));                               {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure HashMD5(var Digest : TMD5Digest; const Buf;  BufSize : LongInt);
var
  Context : TMD5Context;
begin
  fillchar( context, SizeOf( context ), $00 );
  InitMD5(Context);
  UpdateMD5(Context, Buf, BufSize);
  FinalizeMD5(Context, Digest);
end;
{ -------------------------------------------------------------------------- }
procedure InitLMD(var Context : TLMDContext);
var
  ContextEx : TLMDContextEx;
begin
  Move(Context, ContextEx, SizeOf(ContextEx));                       {!!.01}
  ContextEx.DigestIndex := 0;
  TBlock2048(ContextEx.Digest) := TBlock2048(Pi2048);

  ContextEx.KeyIndex := 0;
  ContextEx.KeyInts[0] := $55555555;
  ContextEx.KeyInts[1] := $55555555;
  ContextEx.KeyInts[2] := $55555555;
  ContextEx.KeyInts[3] := $55555555;
  Move(ContextEx, Context, SizeOf(Context));                         {!!.01}
end;

{ -------------------------------------------------------------------------- }
procedure UpdateLMD(var Context : TLMDContext; const Buf; BufSize : LongInt);
var
  ContextEx : TLMDContextEx;                                         {!!.01}
  AA, BB    : LongInt;
  CC, DD    : LongInt;
  I, R      : LongInt;
begin
  Move(Context, ContextEx, SizeOf(ContextEx));                       {!!.01}
  for I := 0 to BufSize - 1 do
    with ContextEx do begin
      {update Digest}
      Digest[DigestIndex] := Digest[DigestIndex] xor
                               TByteArray(Buf)[I];                   {!!.01}
      DigestIndex := DigestIndex + 1;
      if (DigestIndex = SizeOf(Digest)) then
        DigestIndex := 0;

      {update BlockKey}
      Key[KeyIndex] := Key[KeyIndex] xor TByteArray(Buf)[I];         {!!.01}
      KeyIndex := KeyIndex + 1;
      if (KeyIndex = SizeOf(Key) div 2) then begin
        AA := KeyInts[3];
        BB := KeyInts[2];
        CC := KeyInts[1];
        DD := KeyInts[0];

        {mix all the bits around for 4 rounds}
        {achieves avalanche and eliminates funnels}
        for R := 0 to 3 do begin
          AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 7);
          BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 13);
          CC := CC + BB; BB := BB + CC; CC := CC xor (CC shr 17);
          DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 9);
          AA := AA + DD; DD := DD + AA; AA := AA xor (AA shr 3);
          BB := BB + AA; AA := AA + BB; BB := BB xor (BB shl 7);
          CC := CC + BB; BB := BB + CC; CC := CC xor (DD shr 15);
          DD := DD + CC; CC := CC + DD; DD := DD xor (DD shl 11);
        end;

        KeyInts[0] := AA;
        KeyInts[1] := BB;
        KeyInts[2] := CC;
        KeyInts[3] := DD;

        KeyIndex := 0;
      end;
    end;
  Move(ContextEx, Context, SizeOf(Context));                         {!!.01}
end;
{ -------------------------------------------------------------------------- }
procedure FinalizeLMD(var Context : TLMDContext; var Digest; DigestSize : LongInt);
const
  Padding : array [0..7] of Byte = (1, 0, 0, 0, 0, 0, 0, 0);
var
  ContextEx : TLMDContextEx;                                         {!!.01}
  BCContext : TLBCContext;
  I         : Integer;
begin
 {pad with "1", followed by as many "0"s as needed to fill the block}
  Move(Context, ContextEx, SizeOf(ContextEx));                       {!!.01}
  UpdateLMD(Context, Padding, SizeOf(Padding) - ContextEx.KeyIndex);
  Move(Context, ContextEx, SizeOf(ContextEx));                       {!!.01}

  {mix context using block cipher}
  InitEncryptLBC(ContextEx.Key, BCContext, 8, True);
  for I := 0 to (SizeOf(ContextEx.Digest) div SizeOf(TLBCBlock)) - 1 do
    EncryptLBC(BCContext, PLBCBlock(@ContextEx.Digest[I * SizeOf(TLBCBlock)])^);

  {return Digest of requested DigestSize}
  {max digest is 2048-bit, although it could be greater if Pi2048 was larger}
  Move(ContextEx.Digest, Digest, Min(SizeOf(ContextEx.Digest), DigestSize));
end;
{ -------------------------------------------------------------------------- }
procedure HashLMD(var Digest; DigestSize : LongInt; const Buf; BufSize : LongInt);
var
  Context : TLMDContext;
begin
  InitLMD(Context);
  UpdateLMD(Context, Buf, BufSize);
  FinalizeLMD(Context, Digest, DigestSize);
end;
{ -------------------------------------------------------------------------- }
procedure HashMix128(var Digest : LongInt; const Buf;  BufSize : LongInt);
type
  T128BitArray = array[0..0] of T128Bit;
var
  Temp      : T128Bit;
  PTemp     : PByteArray;
  I, L   : LongInt;
begin
  Temp[0] := $243F6A88;  {first 16 bytes of Pi in binary}
  Temp[1] := $93F40317;
  Temp[2] := $0C110496;
  Temp[3] := $C709C289;

  L := BufSize div SizeOf(T128Bit);
  for I := 0 to L - 1 do begin
    Temp[0] := Temp[0] + T128BitArray(Buf)[I][0];                    {!!.01}
    Temp[1] := Temp[1] + T128BitArray(Buf)[I][1];                    {!!.01}
    Temp[2] := Temp[2] + T128BitArray(Buf)[I][2];                    {!!.01}
    Temp[3] := Temp[3] + T128BitArray(Buf)[I][3];                    {!!.01}
    Mix128(Temp);
  end;

  PTemp := @Temp;
  if (BufSize > L * SizeOf(T128Bit)) then begin
    for I := 0 to (BufSize - L * SizeOf(T128Bit)) - 1 do
      PTemp^[I] := PTemp^[I] + TByteArray(Buf)[(L * SizeOf(T128Bit)) + I]; {!!.01}
    Mix128(Temp);
  end;

  Digest := Temp[3];
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure StringHashMix128W(var Digest : LongInt; const Str : Unicodestring);
begin
  HashMix128(Digest, Str[1], Length(Str) * SizeOf(WideChar));
end;
{$ENDIF}

procedure StringHashMix128A(var Digest : LongInt; const Str : AnsiString);
begin
  HashMix128(Digest, Str[1], Length(Str) * SizeOf(AnsiChar));
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure StringHashMD5W(var Digest : TMD5Digest; const Str : UnicodeString);
begin
  HashMD5(Digest, Str[1], Length(Str) * SizeOf(WideChar));
end;
{$ENDIF}

procedure StringHashMD5A(var Digest : TMD5Digest; const Str : AnsiString);
begin
  HashMD5(Digest, Str[1], Length(Str) * SizeOf(AnsiChar));
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure StringHashLMDW(var Digest; DigestSize : LongInt; const Str : UnicodeString);
begin
  HashLMD(Digest, DigestSize, Str[1], Length(Str) * SizeOf(WideChar));
end;
{$ENDIF}

procedure StringHashLMDA(var Digest; DigestSize : LongInt; const Str : AnsiString);
begin
  HashLMD(Digest, DigestSize, Str[1], Length(Str) * SizeOf(AnsiChar));
end;
{ -------------------------------------------------------------------------- }
procedure XorMemPrim(var Mem1;  const Mem2;  Count : Cardinal); register;
asm
  push esi
  push edi

  mov  esi, eax         //esi = Mem1
  mov  edi, edx         //edi = Mem2

  push ecx              //save byte count
  shr  ecx, 2           //convert to dwords
  jz   @Continue

  cld
@Loop1:                 //xor dwords at a time
  mov  eax, [edi]
  xor  [esi], eax
  add  esi, 4
  add  edi, 4
  dec  ecx
  jnz  @Loop1

@Continue:              //handle remaining bytes (3 or less)
  pop  ecx
  and  ecx, 3
  jz   @Done

@Loop2:                 //xor remaining bytes
  mov  al, [edi]
  xor  [esi], al
  inc  esi
  inc  edi
  dec  ecx
  jnz  @Loop2

@Done:
  pop  edi
  pop  esi
end;
{ -------------------------------------------------------------------------- }
procedure XorMem(var Mem1;  const Mem2;  Count : Cardinal);
begin
  XorMemPrim(Mem1, Mem2, Count);
end;

{ == SHA-1 hashing routines ================================================ }
procedure SHA1Clear( var Context : TSHA1Context );
begin
  fillchar( Context, SizeOf( Context ), $00 );
end;
{ -------------------------------------------------------------------------- }
function SHA1SwapByteOrder( n : DWORD ) : DWORD;
begin
  n := ( n shr 24 ) or (( n shr 8 ) and LBMASK_LO )
       or (( n shl 8 ) and LBMASK_HI ) or ( n shl 24 );
  Result := n;
end;
{ -------------------------------------------------------------------------- }
procedure HashSHA1( var Digest : TSHA1Digest; const Buf; BufSize : Longint );
var
  Context : TSHA1Context;
begin
  InitSHA1( Context );
  UpdateSHA1( Context, Buf, BufSize );
  FinalizeSHA1( Context, Digest );
end;
{ -------------------------------------------------------------------------- }
{$IFDEF UNICODE}
procedure StringHashSHA1W(var Digest : TSHA1Digest; const Str : UnicodeString);
begin
  HashSHA1(Digest, Str[1], Length(Str) * SizeOf(WideChar));
end;
{$ENDIF}

procedure StringHashSHA1A(var Digest : TSHA1Digest; const Str : AnsiString);
begin
  HashSHA1(Digest, Str[1], Length(Str) * SizeOf(AnsiChar));
end;
{ -------------------------------------------------------------------------- }
procedure SHA1Hash( var Context : TSHA1Context );
var
  A : DWord;
  B : DWord;
  C : DWord;
  D : DWord;
  E : DWord;

  X : DWord;
  W : array[ 0..79 ] of DWord;

  i : Longint;
begin
  with Context do begin
    sdIndex:= 0;
    Move( sdBuf, W, Sizeof( W ));

    // W := Mt, for t = 0 to 15 : Mt is M sub t
    for i := 0 to 15 do
      W[ i ]:= SHA1SwapByteOrder( W[ i ] );

    // Transform Message block from 16 32 bit words to 80 32 bit words
    // Wt, = ( Wt-3 xor Wt-8 xor Wt-13 xor Wt-16 ) rolL 1 : Wt is W sub t
    for i:= 16 to 79 do
      W[i]:= RolX( W[ i - 3 ] xor W[ i - 8 ] xor W[ i - 14 ] xor W[ i - 16 ], 1 );

    A := sdHash[ 0 ];
    B := sdHash[ 1 ];
    C := sdHash[ 2 ];
    D := sdHash[ 3 ];
    E := sdHash[ 4 ];

    // the four rounds
    for i:= 0 to 19 do begin
      X := RolX( A, 5 ) + ( D xor ( B and ( C xor D ))) + E + W[ i ] + SHA1_K1;
      E := D;
      D := C;
      C := RolX( B, 30 );
      B := A;
      A := X;
    end;

    for i:= 20 to 39 do begin
      X := RolX( A, 5 ) + ( B xor C xor D ) + E + W[ i ] + SHA1_K2;
      E := D;
      D := C;
      C := RolX( B, 30 );
      B := A;
      A := X;
    end;

    for i:= 40 to 59 do begin
      X := RolX( A, 5 ) + (( B and C ) or ( D and ( B or C ))) + E + W[ i ] + SHA1_K3;
      E := D;
      D := C;
      C := RolX( B, 30 );
      B := A;
      A := X;
    end;

    for i:= 60 to 79 do
    begin
      X := RolX( A, 5 ) + ( B xor C xor D ) + E + W[ i ] + SHA1_K4;
      E := D;
      D := C;
      C := RolX( B, 30 );
      B := A;
      A := X;
    end;

    sdHash[ 0 ]:= sdHash[ 0 ] + A;
    sdHash[ 1 ]:= sdHash[ 1 ] + B;
    sdHash[ 2 ]:= sdHash[ 2 ] + C;
    sdHash[ 3 ]:= sdHash[ 3 ] + D;
    sdHash[ 4 ]:= sdHash[ 4 ] + E;

    FillChar( W, Sizeof( W ), $00 );
    FillChar( sdBuf, Sizeof( sdBuf ), $00 );
  end;
end;
{ -------------------------------------------------------------------------- }
procedure SHA1UpdateLen( var Context : TSHA1Context; Len : DWord );
begin
  Inc( Context.sdLo,( Len shl 3 ));
  if Context.sdLo < ( Len shl 3 ) then
    Inc( Context.sdHi );
  Inc( Context.sdHi, Len shr 29 );
end;
{ -------------------------------------------------------------------------- }
procedure InitSHA1( var Context : TSHA1Context );
begin
  SHA1Clear( Context );
  Context.sdHash[ 0 ] := SHA1_A;
  Context.sdHash[ 1 ] := SHA1_B;
  Context.sdHash[ 2 ] := SHA1_C;
  Context.sdHash[ 3 ] := SHA1_D;
  Context.sdHash[ 4 ] := SHA1_E;
end;
{ -------------------------------------------------------------------------- }
procedure UpdateSHA1( var Context : TSHA1Context; const Buf; BufSize: Longint );
var
  PBuf: ^Byte;
begin
  with Context do begin
    SHA1UpdateLen( Context, BufSize );
    PBuf := @Buf;
    while BufSize > 0 do begin
      if ( Sizeof( sdBuf ) - sdIndex ) <= DWord( BufSize ) then begin
        Move( PBuf^, sdBuf[ sdIndex ], Sizeof( sdBuf ) - sdIndex );
        Dec( BufSize, Sizeof( sdBuf ) - sdIndex );
        Inc( PBuf, Sizeof( sdBuf ) - sdIndex );
        SHA1Hash( Context );
      end else begin
        Move( PBuf^, sdBuf[ sdIndex ], BufSize );
        Inc( sdIndex, BufSize );
        BufSize := 0;
      end;
    end;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure FinalizeSHA1( var Context : TSHA1Context; var Digest : TSHA1Digest );
begin
  with Context do begin
    sdBuf[ sdIndex ] := $80;

    if sdIndex >= 56 then
      SHA1Hash( Context );

    PDWord( @sdBuf[ 56 ])^ := SHA1SwapByteOrder( sdHi );
    PDWord( @sdBuf[ 60 ])^ := SHA1SwapByteOrder( sdLo );

    SHA1Hash( Context );

    sdHash[ 0 ] := SHA1SwapByteOrder( sdHash[ 0 ]);
    sdHash[ 1 ] := SHA1SwapByteOrder( sdHash[ 1 ]);
    sdHash[ 2 ] := SHA1SwapByteOrder( sdHash[ 2 ]);
    sdHash[ 3 ] := SHA1SwapByteOrder( sdHash[ 3 ]);
    sdHash[ 4 ] := SHA1SwapByteOrder( sdHash[ 4 ]);

    Move( sdHash, Digest, Sizeof( Digest ));
    SHA1Clear( Context );
  end;
end;


{ == Rijndael ============================================================== }
function RdlSubVector(v : TRDLVector) : TRDLVector;
  { S-Box substitution }
begin
  Result.bt[0] := RdlSBox[v.bt[0]];
  Result.bt[1] := RdlSBox[v.bt[1]];
  Result.bt[2] := RdlSBox[v.bt[2]];
  Result.bt[3] := RdlSBox[v.bt[3]];
end;
{ ------------------------------------------------------------------- }
function RdlRotateVector(v : TRDLVector; Count : Byte) : TRDLVector;
  { rotate vector (count bytes) to the right, e.g. }
  { |3 2 1 0| -> |0 3 2 1| for Count = 1 }
var
  i : Byte;
begin
  i := Count mod 4;
  Result.bt[0] := v.bt[i];
  Result.bt[1] := v.bt[(i+1) mod 4];
  Result.bt[2] := v.bt[(i+2) mod 4];
  Result.bt[3] := v.bt[(i+3) mod 4];
end;
{ -------------------------------------------------------------------------- }
procedure RdlRound(const RoundKey : TRDLBlock; var State : TRDLBlock; Final : Boolean);
  { Rijndael round transformation }
  { entire routine rewritten for optimization }                      {!!.01}
var
  i : Integer;
  e : TRDLVectors;
begin
  for i := 0 to 3 do begin
    if not Final then begin
      e[i].dw := RDL_T0[TRDlVectors(State)[(i+0) mod 4].bt[0]] xor
                 RDL_T1[TRDlVectors(State)[(i+1) mod 4].bt[1]] xor
                 RDL_T2[TRDlVectors(State)[(i+2) mod 4].bt[2]] xor
                 RDL_T3[TRDlVectors(State)[(i+3) mod 4].bt[3]]
    end else begin
      e[i].bt[0] := RDLSBox[TRDlVectors(State)[(i+0) mod 4].bt[0]];
      e[i].bt[1] := RDLSBox[TRDlVectors(State)[(i+1) mod 4].bt[1]];
      e[i].bt[2] := RDLSBox[TRDlVectors(State)[(i+2) mod 4].bt[2]];
      e[i].bt[3] := RDLSBox[TRDlVectors(State)[(i+3) mod 4].bt[3]];
    end;
  end;
  XorMemPrim(e, RoundKey, SizeOf(TRDLBlock));
  State := TRDLBlock(e);
end;
{ -------------------------------------------------------------------------- }
procedure RdlInvRound(const RoundKey : TRDLBlock; var State : TRDLBlock; First : Boolean);
  { Rijndael inverse round transformation }
  { entire routine rewritten for optimization }                      {!!.01}
var
  i : Integer;
  r : TRDLVectors;
  e : TRDLVector;
begin
  XorMemPrim(State, RoundKey, SizeOf(TRDLBlock));
  for i := 0 to 3 do begin
    if not First then begin
      e.dw := RDL_InvT0[TRDlVectors(State)[i].bt[0]] xor
              RDL_InvT1[TRDlVectors(State)[i].bt[1]] xor
              RDL_InvT2[TRDlVectors(State)[i].bt[2]] xor
              RDL_InvT3[TRDlVectors(State)[i].bt[3]];
      r[(i+0) mod 4].bt[0] := RDLInvSBox[e.bt[0]];
      r[(i+1) mod 4].bt[1] := RDLInvSBox[e.bt[1]];
      r[(i+2) mod 4].bt[2] := RDLInvSBox[e.bt[2]];
      r[(i+3) mod 4].bt[3] := RDLInvSBox[e.bt[3]];
    end else begin
      r[i].bt[0] := RDLInvSBox[TRDlVectors(State)[(i+0) mod 4].bt[0]];
      r[i].bt[1] := RDLInvSBox[TRDlVectors(State)[(i+3) mod 4].bt[1]];
      r[i].bt[2] := RDLInvSBox[TRDlVectors(State)[(i+2) mod 4].bt[2]];
      r[i].bt[3] := RDLInvSBox[TRDlVectors(State)[(i+1) mod 4].bt[3]];
    end;
  end;
  State := TRDLBlock(r);
end;
{ ------------------------------------------------------------------- }
procedure EncryptRDL(const Context : TRDLContext; var Block : TRDLBlock);
  { encrypt/decrypt block ECB mode }
var
  i : Integer;
begin
  if Context.Encrypt then begin
    XorMemPrim(Block, Context.Rk[0], SizeOf(TRDLBlock));
    for i := 1 to (Context.Rounds - 1) do
      RdlRound(Context.Rk[i], Block, False);
    RdlRound(Context.Rk[Context.Rounds], Block, True);
  end else begin
    RdlInvRound(Context.Rk[Context.Rounds], Block, True);
    for i := (Context.Rounds - 1) downto 1 do
      RdlInvRound(Context.Rk[i], Block, False);
    XorMemPrim(Block, Context.Rk[0], SizeOf(TRDLBlock));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure EncryptRDLCBC(const Context : TRDLContext;
            const Prev : TRDLBlock; var Block : TRDLBlock);
  { encrypt/decrypt block CBC mode }
begin
  if Context.Encrypt then begin
    XorMemPrim(Block, Prev, SizeOf(Block));
    EncryptRDL(Context, Block);
  end else begin
    EncryptRDL(Context, Block);
    XorMemPrim(Block, Prev, SizeOf(Block));
  end;
end;
{ -------------------------------------------------------------------------- }
procedure InitEncryptRDL(const Key; KeySize : Longint;
            var Context : TRDLContext; Encrypt : Boolean);
  { Rijndael key expansion }
var
  i : Integer;
  Nk : Byte;
  temp : TRDLVector;
  Sk : Longint;
begin
  { prepare context }
  FillChar(Context, SizeOf(Context), #0);
  Context.Encrypt := Encrypt;
  Sk := Min(KeySize, SizeOf(Context.Rk));
  Move(Key, Context.Rk, Sk);
  Nk := KeySize div 4;       { # key columns }
  if (Nk > RDLNk256) then
    Nk := RDLNk256
  else if (Nk < RDLNk128) then
    Nk := RDLNk128;
  Context.Rounds := 6 + Nk;

  { expand key into round keys }
  for i := Nk to (4 * (Context.Rounds + 1)) do begin
    temp := Context.W[i-1];
    if (Nk in [RDLNk128, RDLNk192]) then
      begin
        if (i mod Nk) = 0 then
          temp.dw := RdlSubVector(RdlRotateVector(temp, 1)).dw xor RCon[i div Nk];
        Context.W[i].dw := Context.W[i - Nk].dw xor temp.dw;
      end
    else  { Nk = RDLNk256 }
      begin
        if (i mod Nk) = 0 then
          temp.dw := RdlSubVector(RdlRotateVector(temp, 1)).dw xor RCon[i div Nk]
        else if (i mod Nk) = 4 then
          temp := RdlSubVector(Temp);
        Context.W[i].dw := Context.W[i - Nk].dw xor temp.dw;
      end;
  end;
end;

procedure StringHashELF(var Digest : LongInt; const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  StringHashELFW(Digest, Str);
  {$ELSE}
  StringHashELFA(Digest, Str);
  {$ENDIF}
end;

procedure StringHashLMD(var Digest; DigestSize : LongInt; const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  StringHashLMDW(Digest, DigestSize, Str);
  {$ELSE}
  StringHashLMDA(Digest, DigestSize, Str);
  {$ENDIF}
end;

procedure StringHashMD5(var Digest : TMD5Digest; const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  StringHashMD5W(Digest, Str);
  {$ELSE}
  StringHashMD5A(Digest, Str);
  {$ENDIF}
end;

procedure StringHashMix128(var Digest : LongInt; const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  StringHashMix128W(Digest, Str);
  {$ELSE}
  StringHashMix128A(Digest, Str);
  {$ENDIF}
end;

procedure StringHashSHA1(var Digest : TSHA1Digest; const Str : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  StringHashSHA1W(Digest, Str);
  {$ELSE}
  StringHashSHA1A(Digest, Str);
  {$ENDIF}
end;

end.
