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
 * Contributor(s): Roman Kassebaum
 *
 * ***** END LICENSE BLOCK ***** *)
{*********************************************************}
{*                  LBASYM.PAS 2.08                      *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbAsym;
  {-Asymmetric key encryption classes}

interface

uses
  System.Classes, System.SysUtils, LbBigInt, LbClass, LbConst;

type
  PByte = ^Byte;

  TLbAsymKeySize = (aks128, aks256, aks512, aks768, aks1024);

const
  cLbDefAsymKeySize = aks512;
  cLbAsymKeyBytes : array[TLbAsymKeySize] of Word =
    (cBytes128, cBytes256, cBytes512, cBytes768, cBytes1024);

type
  TLbProgressEvent = procedure(Sender : TObject; var Abort : Boolean) of object;

  TLbAsymmetricKey = class(TObject)
  strict private
    FEncoding: TEncoding;
    FPassphrase : string;
    procedure MovePtr(var Ptr : PByte; var Max : Integer );
    procedure MovePtrCount(var Ptr : PByte; var Max : Integer; Count : Integer);
  strict protected
    FKeySize  : TLbAsymKeySize;
    procedure CreateASN1(var Buf; var BufLen : Integer; Tag : Byte);
    function CreateASNKey(Input : pByteArray; Length : Integer): Integer; virtual; abstract;
    function EncodeASN1(biValue : TLbBigInt; var pBuf : PByteArray; var MaxLen : Integer): Integer;
    function GetASN1StructLen(var input : pByte; var len : Integer): Integer;
    function GetASN1StructNum(var input : pByte; var len : Integer): Integer;
    function GetBytes(const AString: string): TBytes;
    procedure ParseASN1(var input : pByte; var length : Integer; biValue : TLbBigInt);
    function ParseASNKey(Input : pByte; Length : Integer): boolean; virtual; abstract;
    procedure SetKeySize(Value : TLbAsymKeySize); virtual;
  public
    constructor Create(aKeySize : TLbAsymKeySize); virtual;
    procedure Assign(aKey : TLbAsymmetricKey); virtual;

    procedure LoadFromStream(aStream : TStream); virtual; { as ASN.1 set }
    procedure StoreToStream(aStream : TStream); virtual; { as ASN.1 set }
    procedure LoadFromFile(aFileName : string); virtual; { as ASN.1 set }
    procedure StoreToFile(aFileName : string); virtual; { as ASN.1 set }

    property Encoding: TEncoding read FEncoding write FEncoding;
    property KeySize : TLbAsymKeySize read FKeySize write SetKeySize;
    property Passphrase : string read FPassphrase write FPassphrase;
  end;

  TLbAsymmetricCipher = class(TLbCipher)
  strict private
    FOnProgress : TLbProgressEvent;
  strict protected
    FKeySize: TLbAsymKeySize;
    procedure SetKeySize(Value : TLbAsymKeySize); virtual;
  public
    constructor Create(AOwner : TComponent); override;
    procedure GenerateKeyPair; virtual; abstract;
    property KeySize : TLbAsymKeySize read FKeySize write SetKeySize;
    property OnProgress : TLbProgressEvent read FOnProgress write FOnProgress;
  end;

  TLbSignature = class(TLbBaseComponent)
  strict private
  strict protected
    FKeySize: TLbAsymKeySize;
    FOnProgress: TLbProgressEvent;
    procedure SetKeySize(Value : TLbAsymKeySize); virtual;
  public
    constructor Create(AOwner : TComponent); override;

    procedure GenerateKeyPair; virtual; abstract;

    procedure SignBuffer(const Buf; BufLen : Cardinal); virtual; abstract;
    procedure SignFile(const AFileName : string); virtual; abstract;
    procedure SignStream(AStream : TStream); virtual; abstract;
    procedure SignString(const AStr : string); virtual; abstract;

    function  VerifyBuffer(const Buf; BufLen : Cardinal) : Boolean; virtual; abstract;
    function  VerifyFile(const AFileName : string) : Boolean; virtual; abstract;
    function  VerifyStream(AStream : TStream) : Boolean; virtual; abstract;
    function  VerifyString(const AStr : string): Boolean; virtual; abstract;
    property KeySize : TLbAsymKeySize read FKeySize write SetKeySize;
    property OnProgress : TLbProgressEvent read FOnProgress write FOnProgress;
  end;

implementation

uses
  LbCipher, LbProc, LbUtils;

{ TLbAsymmetricKey }

constructor TLbAsymmetricKey.Create(aKeySize : TLbAsymKeySize);
begin
  inherited Create;
  FKeySize := aKeySize;
  FEncoding :=  TEncoding.ANSI;
end;

procedure TLbAsymmetricKey.Assign(aKey : TLbAsymmetricKey);
begin
  FKeySize := aKey.KeySize;
end;

procedure TLbAsymmetricKey.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
end;

procedure TLbAsymmetricKey.MovePtr(var Ptr : PByte; var Max : Integer);
  { increment buffer pointer and decrement Max }
begin
  Dec(Max);
  if (Max < 0) then
    raise Exception.Create(sASNKeyBadKey);
  Inc(Ptr);
end;

procedure TLbAsymmetricKey.MovePtrCount(var Ptr : PByte; var Max : Integer; Count : Integer);
  { increment buffer pointer and decrement Max by Count bytes }
begin
  Dec(Max, Count);
  if (Max < 0) then
    raise Exception.Create(sASNKeyBadKey);
  Inc(Ptr, Count);
end;

function TLbAsymmetricKey.GetASN1StructLen(var input : pByte; var len : Integer): Integer;
  { return length of ASN.1 structure in buffer located at Input }
var
  Tmp_int : Integer;
  TagLen  : Integer;
  Tmp_ptr : PByte;
  Max     : Integer;
  IsHighBit : boolean;
begin
  Max := Len;
  Tmp_ptr := Input;
  tagLen := $00;

  isHighBit := ( tmp_ptr^ and HIGH_BIT_MASK ) = HIGH_BIT_MASK;
  tmp_int := tmp_ptr^ and BIT_MASK_7F;

  MovePtr( tmp_ptr, max );
  if( isHighBit )then begin
    while( tmp_int > 0 )do begin
      tagLen := ( tagLen shl 8 ) or  tmp_ptr^;
      MovePtr( tmp_ptr, max );
      dec( tmp_int );
    end;
  end else
    tagLen := tmp_int;

  result := tagLen;
  len := max;
  input := tmp_ptr;
end;

function TLbAsymmetricKey.GetASN1StructNum(var input : pByte; var len : Integer): Integer;
  { return ID of ASN.1 structure in buffer located at Input }
var
  tmp_int : Integer;
  tagNum : Integer;
  tmp_ptr : pBYTE;
  max : Integer;
  hold_byte : BYTE;
  tag : Integer;
begin
  max := len;
  tmp_ptr := input;
  hold_byte := tmp_ptr^;
  tagNum := ( hold_byte and ASN1_TAG_NUM_MASK );

  if( tagNum = ASN1_TYPE_HIGH_TAG_NUMBER )then begin
    MovePtr( tmp_ptr, max );
    tmp_int := 0;
    while(( tmp_ptr^ and HIGH_BIT_MASK ) > 0 )do begin
      tmp_int := tmp_int shl 7;
      MovePtr( tmp_ptr, max );
      tmp_int := tmp_int or ( tmp_ptr^ and BIT_MASK_7F );
    end;
    tmp_int := tmp_int shl 7;
    MovePtr( tmp_ptr, max );
    tmp_int := tmp_int or ( tmp_ptr^ and BIT_MASK_7F );
    tag := tmp_int;
  end else begin
    tag := tagNum;
    MovePtr( tmp_ptr, max );
  end;
  len := max;
  input := tmp_ptr;
  result := tag;
end;

procedure TLbAsymmetricKey.CreateASN1(var Buf; var BufLen : Integer; Tag : Byte);
  { create an ASN.1 format buffer }
var
  i : Integer;
  x : Integer;
  tmp : array[0..4095] of Byte;
  TagSize : Integer;
  tmp_Len : Integer;
begin

  if (BufLen > SizeOf(tmp)) then
    raise Exception.Create(sASNKeyBadKey);

  TagSize := 0;
  tmp_Len := BufLen;
  tmp[TagSize] := Tag;
  Inc(TagSize);
  if (BufLen > BIT_MASK_7F) then begin
    i := BufLen div $FF;
    if (i = 0) then
      i := 1;
    tmp[TagSize] := ($80 or i);
    Inc(TagSize , i);
    for x := 1 to i do begin
      tmp[TagSize] := BufLen and $000000FF;
      BufLen := BufLen shr 8;
      Dec(TagSize);
    end;
    Inc(TagSize, i+1);
  end else begin
    tmp[TagSize] := BufLen;
    Inc(TagSize)
  end;

  BufLen := tmp_Len + TagSize;
  if (BufLen > SizeOf(tmp)) then
    raise Exception.Create(sASNKeyBadKey);

  Move(Buf, tmp[TagSize], tmp_Len);
  Move(tmp, Buf, BufLen);
end;

function TLbAsymmetricKey.EncodeASN1(biValue : TLbBigInt; var pBuf : PByteArray; var MaxLen : Integer): Integer;
const
  TAG02 = $02;
var
  Pad : Boolean;
begin
  Result := biValue.Size;
  Pad := (biValue.GetByteValue(1) > $80);
  if Pad then
    Inc(Result);
  if (Result > MaxLen) then
    raise Exception.Create(sASNKeyBadKey);

  FillChar(pBuf^, Result, #0);
  biValue.ToBuffer(pBuf^, Result);

  if Pad then begin
    Move(pBuf^[0], pBuf^[1], Result-1);
    pBuf^[0] := $00;
  end;

  CreateASN1(pBuf^, Result, TAG02);
  MovePtrCount(PByte(pBuf), MaxLen, Result);
end;

function TLbAsymmetricKey.GetBytes(const AString: string): TBytes;
begin
  Result := Encoding.GetBytes(AString);
end;

procedure TLbAsymmetricKey.LoadFromStream(aStream : TStream);
  { load key from ASN.1 format stream (decrypt if necessary) }
var
  KeyBuf : array[0..4096] of Byte;
  Len : Integer;
  MemStream : TMemoryStream;
  BFKey : TKey128;
begin
  FillChar(KeyBuf, SizeOf(KeyBuf), #0);
  aStream.Position := 0;

  { decrypt stream first if passphrase in not empty }
  if (FPassphrase <> '') then begin
    MemStream := TMemoryStream.Create;
    try
      TMD5Encrypt.StringHashMD5(TMD5Digest(BFKey), GetBytes(FPassphrase));
      TBlowfishEncrypt.BFEncryptStream(aStream, MemStream, BFKey, False);
      Len := MemStream.Size;
      if (Len > SizeOf(KeyBuf)) then
        raise Exception.Create(sASNKeyBadKey);
      MemStream.Position := 0;
      MemStream.Read(KeyBuf, Len);
    finally
      MemStream.Free;
    end;
  end else begin
    Len := aStream.Size;
    if (Len > SizeOf(KeyBuf)) then
      raise Exception.Create(sASNKeyBadKey);
    aStream.Read(KeyBuf, Len);
  end;
  ParseASNKey(pByte(@KeyBuf), Len);
  FillChar(KeyBuf, SizeOf(KeyBuf), #0);
end;

procedure TLbAsymmetricKey.StoreToStream(aStream : TStream);
  { save key to ASN.1 format stream (encrypt if necessary) }
var
  KeyBuf : array[0..4096] of Byte;
  Len : Integer;
  MemStream : TMemoryStream;
  BFKey : TKey128;
begin
  FillChar(KeyBuf, SizeOf(KeyBuf), #0);
  Len := CreateASNKey(@KeyBuf, SizeOf(KeyBuf));

  { encrypt buffer first if passphrase in not empty }
  if (FPassphrase <> '') then begin
    MemStream := TMemoryStream.Create;
    try
      MemStream.Write(KeyBuf, Len);
      MemStream.Position := 0;
      TMD5Encrypt.StringHashMD5(TMD5Digest(BFKey), GetBytes(FPassphrase));
      TBlowfishEncrypt.BFEncryptStream(MemStream, aStream, BFKey, True);
    finally
      MemStream.Free;
    end;
  end else
    aStream.Write(KeyBuf, Len);

  FillChar(KeyBuf, SizeOf(KeyBuf), #0);
end;

procedure TLbAsymmetricKey.LoadFromFile(aFileName : string);
  { load key from ASN.1 format file (decrypt if necessary) }
var
  FS : TFileStream;
begin
  FS := TFileStream.Create(aFileName, fmOpenRead);
  try
    LoadFromStream(FS);
  finally
    FS.Free;
  end;
end;

procedure TLbAsymmetricKey.StoreToFile(aFileName : string);
  { save key to ASN.1 format file (encrypt if necessary) }
var
  FS : TFileStream;
begin
  FS := TFileStream.Create(aFileName, fmCreate);
  try
    StoreToStream(FS);
  finally
    FS.Free;
  end;
end;

procedure TLbAsymmetricKey.ParseASN1(var input : pByte; var length : Integer; biValue : TLbBigInt);
var
  tag : Integer;
  len : Integer;
begin
  tag := GetASN1StructNum( input, length );
  len := GetASN1StructLen( input, length );

  if( len > length )then
    raise Exception.Create(sASNKeyBadKey);

  if( tag = ASN1_TYPE_Integer )then begin
    if( input^ = $00 ) and ( pByteArray( input )^[ 1 ] > $80 )then begin
      MovePtr( input, length );
      dec( len );
    end;
    biValue.CopyBuffer( input^, len );
    inc( pByte( input ), len );
    length := length - len;
  end else
    raise Exception.Create(sASNKeyBadKey);
end;

{ TLbAsymmetricCipher }

constructor TLbAsymmetricCipher.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);

  FKeySize := cLbDefAsymKeySize;
end;

procedure TLbAsymmetricCipher.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
end;

{ TLbSignature }

constructor TLbSignature.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);

  FKeySize := cLbDefAsymKeySize;
end;

procedure TLbSignature.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
end;

end.

