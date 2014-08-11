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
 * Contributor(s): 
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
  Classes, SysUtils, LbBigInt, LbClass, LbConst;

type
  pByte = ^Byte;

type
  TLbAsymKeySize = (aks128, aks256, aks512, aks768, aks1024);

const
  cLbDefAsymKeySize = aks512;
  cLbAsymKeyBytes : array[TLbAsymKeySize] of Word =
    (cBytes128, cBytes256, cBytes512, cBytes768, cBytes1024);

type
  TLbProgressEvent = procedure(Sender : TObject; var Abort : Boolean) of object;


{ TLbAsymmetricKey }
type
  TLbAsymmetricKey = class
    protected {private}
      FKeySize  : TLbAsymKeySize;
      FPassphrase : AnsiString;
      procedure SetKeySize(Value : TLbAsymKeySize); virtual;
{!!.06}
      procedure MovePtr(var Ptr : PByte; var Max : Integer );
      procedure MovePtrCount(var Ptr : PByte; var Max : Integer; Count : Integer);
      function GetASN1StructLen( var input : pByte; var len : Integer ) : Integer;
      function GetASN1StructNum ( var input : pByte; var len : Integer ) : Integer;
      procedure CreateASN1(var Buf; var BufLen : Integer; Tag : Byte);
      procedure ParseASN1(var input : pByte; var length : Integer; biValue : TLbBigInt);
      function EncodeASN1(biValue : TLbBigInt; var pBuf : PByteArray; var MaxLen : Integer) : Integer;
      function  CreateASNKey(Input : pByteArray; Length : Integer) : Integer; virtual; abstract;
      function ParseASNKey(Input : pByte; Length : Integer) : boolean; virtual; abstract;
{!!.06}

    public {methods}
      constructor Create(aKeySize : TLbAsymKeySize); virtual;
      destructor Destroy; override;
      procedure Assign(aKey : TLbAsymmetricKey); virtual;
{!!.06}
      procedure LoadFromStream(aStream : TStream); virtual; { as ASN.1 set }
      procedure StoreToStream(aStream : TStream); virtual; { as ASN.1 set }
      procedure LoadFromFile(aFileName : string); virtual; { as ASN.1 set }
      procedure StoreToFile(aFileName : string); virtual; { as ASN.1 set }
{!!.06}

    public {properties}
      property KeySize : TLbAsymKeySize
        read FKeySize write SetKeySize;
      property Passphrase : AnsiString
        read FPassphrase write FPassphrase;
  end;


{ TLbAsymmetricCipher }
type
  TLbAsymmetricCipher = class(TLbCipher)
    protected {private}
      FKeySize    : TLbAsymKeySize;
      FOnProgress : TLbProgressEvent;
      procedure SetKeySize(Value : TLbAsymKeySize); virtual;
    public {methods}
      constructor Create(AOwner : TComponent); override;
      destructor Destroy; override;
      procedure GenerateKeyPair; virtual; abstract;
    public {properties}
      property KeySize : TLbAsymKeySize
        read FKeySize write SetKeySize;
      property OnProgress : TLbProgressEvent
        read FOnProgress write FOnProgress;
    end;


{ TLbSignature }
type
  TLbSignature = class(TLbBaseComponent)
    protected {private}
      FKeySize : TLbAsymKeySize;
      FOnProgress : TLbProgressEvent;
      procedure SetKeySize(Value : TLbAsymKeySize); virtual;
    public {methods}
      constructor Create(AOwner : TComponent); override;
      destructor Destroy; override;

      procedure GenerateKeyPair; virtual; abstract;

      procedure SignBuffer(const Buf; BufLen : Cardinal); virtual; abstract;
      procedure SignFile(const AFileName : string); virtual; abstract;
      procedure SignStream(AStream : TStream); virtual; abstract;
      procedure SignString(const AStr : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
      procedure SignStringA(const AStr : AnsiString); virtual; abstract;
      {$IFDEF UNICODE}
      procedure SignStringW(const AStr : UnicodeString); virtual; abstract;
      {$ENDIF}

      function  VerifyBuffer(const Buf; BufLen : Cardinal) : Boolean; virtual; abstract;
      function  VerifyFile(const AFileName : string) : Boolean; virtual; abstract;
      function  VerifyStream(AStream : TStream) : Boolean; virtual; abstract;
      function  VerifyString(const AStr : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}) : Boolean;
      function  VerifyStringA(const AStr : AnsiString) : Boolean; virtual; abstract;
      {$IFDEF UNICODE}
      function  VerifyStringW(const AStr : UnicodeString) : Boolean; virtual; abstract;
      {$ENDIF}
    public {properties}
      property KeySize : TLbAsymKeySize
        read FKeySize write SetKeySize;
      property OnProgress : TLbProgressEvent
        read FOnProgress write FOnProgress;
    end;



implementation

uses
  LbCipher, LbProc, LbUtils;


{ == TLbAsymmetricKey ====================================================== }
constructor TLbAsymmetricKey.Create(aKeySize : TLbAsymKeySize);
begin
  FKeySize := aKeySize;
end;
{ -------------------------------------------------------------------------- }
destructor TLbAsymmetricKey.Destroy;
begin
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAsymmetricKey.Assign(aKey : TLbAsymmetricKey);
begin
  FKeySize := aKey.KeySize;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAsymmetricKey.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
end;
{ -------------------------------------------------------------------------- }
{!!.06}
procedure TLbAsymmetricKey.MovePtr(var Ptr : PByte; var Max : Integer);
  { increment buffer pointer and decrement Max }
begin
  Dec(Max);
  if (Max < 0) then
    raise Exception.Create(sASNKeyBadKey);
  Inc(Ptr);
end;
{ -------------------------------------------------------------------------- }
{!!.06}
procedure TLbAsymmetricKey.MovePtrCount(var Ptr : PByte; var Max : Integer;
                                        Count : Integer);
  { increment buffer pointer and decrement Max by Count bytes }
begin
  Dec(Max, Count);
  if (Max < 0) then
    raise Exception.Create(sASNKeyBadKey);
  Inc(Ptr, Count);
end;
{ -------------------------------------------------------------------------- }
{!!.06}
function TLbAsymmetricKey.GetASN1StructLen(var Input : PByte; var Len : Integer) : Integer;
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
{ -------------------------------------------------------------------------- }
{!!.06}
function TLbAsymmetricKey.GetASN1StructNum (var Input : PByte; var Len : Integer) : Integer;
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
{ -------------------------------------------------------------------------- }
{!!.06}
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
{ -------------------------------------------------------------------------- }
{!!.06}
function TLbAsymmetricKey.EncodeASN1(biValue : TLbBigInt; var pBuf : PByteArray;
                                     var MaxLen : Integer) : Integer;
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
{ -------------------------------------------------------------------------- }
{!!.06}
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
      StringHashMD5A(TMD5Digest(BFKey), FPassphrase);
      BFEncryptStream(aStream, MemStream, BFKey, False);
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
{ -------------------------------------------------------------------------- }
{!!.06}
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
      StringHashMD5A(TMD5Digest(BFKey), FPassphrase);
      BFEncryptStream(MemStream, aStream, BFKey, True);
    finally
      MemStream.Free;
    end;
  end else
    aStream.Write(KeyBuf, Len);

  FillChar(KeyBuf, SizeOf(KeyBuf), #0);
end;
{ -------------------------------------------------------------------------- }
{!!.06}
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
{ -------------------------------------------------------------------------- }
{!!.06}
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
{ -------------------------------------------------------------------------- }
{!!.06}
procedure TLbAsymmetricKey.ParseASN1(var input : pByte; var length : Integer;
                                     biValue : TLbBigInt);
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


{ == TLbAsymmetricCipher =================================================== }
constructor TLbAsymmetricCipher.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);

  FKeySize := cLbDefAsymKeySize;
end;
{ -------------------------------------------------------------------------- }
destructor TLbAsymmetricCipher.Destroy;
begin
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAsymmetricCipher.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
end;


{ == TLbSignature ========================================================== }
constructor TLbSignature.Create(AOwner : TComponent);
begin
  inherited Create(AOwner);

  FKeySize := cLbDefAsymKeySize;
end;
{ -------------------------------------------------------------------------- }
destructor TLbSignature.Destroy;
begin
  inherited Destroy;
end;
{ -------------------------------------------------------------------------- }
procedure TLbSignature.SetKeySize(Value : TLbAsymKeySize);
begin
  FKeySize := Value;
end;

procedure TLbSignature.SignString(const AStr: {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF});
begin
  {$IFDEF LOCKBOXUNICODE}
  SignStringW(AStr);
  {$ELSE}
  SignStringA(AStr);
  {$ENDIF}
end;

function TLbSignature.VerifyString(const AStr: {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}): Boolean;
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := VerifyStringW(AStr);
  {$ELSE}
  Result := VerifyStringA(AStr);
  {$ENDIF}
end;

end.

