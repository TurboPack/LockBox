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
{*                   LBSTRING.PAS 2.08                   *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

{$H+}  {turn on huge strings}


unit LbString;
  {-string encryption routines}

interface

uses
  Classes, SysUtils, LbCipher;

procedure BFEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
procedure BFEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
procedure DESEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean);
procedure DESEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean);
procedure TripleDESEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
procedure TripleDESEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
procedure RDLEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean);
procedure RDLEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean);

procedure BFEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
procedure BFEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
procedure DESEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey64; Encrypt : Boolean);
procedure DESEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey64; Encrypt : Boolean);
procedure TripleDESEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
procedure TripleDESEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
procedure RDLEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean);
procedure RDLEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean);

{$IFDEF UNICODE}
procedure BFEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
procedure BFEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
procedure DESEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean);
procedure DESEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean);
procedure TripleDESEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
procedure TripleDESEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
procedure RDLEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean);
procedure RDLEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean);
{$ENDIF}

function BFEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function BFEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function DESEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function DESEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function TripleDESEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function TripleDESEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function RDLEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
function RDLEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};

function BFEncryptStringExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
function BFEncryptStringCBCExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
function DESEncryptStringExA(const InString : AnsiString;
            const Key : TKey64; Encrypt : Boolean) : AnsiString;
function DESEncryptStringCBCExA(const InString : AnsiString;
            const Key : TKey64; Encrypt : Boolean) : AnsiString;
function TripleDESEncryptStringExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
function TripleDESEncryptStringCBCExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
function RDLEncryptStringExA(const InString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean) : AnsiString;
function RDLEncryptStringCBCExA(const InString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean) : AnsiString;

{$IFDEF UNICODE}
function BFEncryptStringExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
function BFEncryptStringCBCExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
function DESEncryptStringExW(const InString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean) : UnicodeString;
function DESEncryptStringCBCExW(const InString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean) : UnicodeString;
function TripleDESEncryptStringExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
function TripleDESEncryptStringCBCExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
function RDLEncryptStringExW(const InString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean) : UnicodeString;
function RDLEncryptStringCBCExW(const InString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean) : UnicodeString;
{$ENDIF}

procedure LbDecodeBase64A(InStream, OutStream : TStream);
procedure LbEncodeBase64A(InStream, OutStream : TStream);

procedure LbDecodeBase64W(InStream, OutStream : TStream);
procedure LbEncodeBase64W(InStream, OutStream : TStream);

implementation

uses
  LbProc;

{$IFDEF UNICODE} {$HIGHCHARUNICODE OFF} {$ENDIF}
const
  Lb64Table : array[0..63] of AnsiChar = ( #65,  #66,  #67,  #68,  #69,
         #70,  #71,  #72,  #73,  #74,  #75,  #76,  #77,  #78,  #79,
         #80,  #81,  #82,  #83,  #84,  #85,  #86,  #87,  #88,  #89,
         #90,  #97,  #98,  #99, #100, #101, #102, #103, #104, #105,
        #106, #107, #108, #109, #110, #111, #112, #113, #114, #115,
        #116, #117, #118, #119, #120, #121, #122,  #48,  #49,  #50,
         #51,  #52,  #53,  #54,  #55,  #56,  #57,  #43,  #47);

const
  LbD64Table : array[43..122] of Byte = ($3E, $7F, $7F, $7F, $3F, $34,
      $35, $36, $37, $38, $39, $3A, $3B, $3C, $3D, $7F, $7F, $7F, $7F,
      $7F, $7F, $7F, $00, $01, $02, $03, $04, $05, $06, $07, $08, $09,
      $0A, $0B, $0C, $0D, $0E, $0F, $10, $11, $12, $13, $14, $15, $16,
      $17, $18, $19, $7F, $7F, $7F, $7F, $7F, $7F, $1A, $1B, $1C, $1D,
      $1E, $1F, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $2A,
      $2B, $2C, $2D, $2E, $2F, $30, $31, $32, $33);


{ == Base64 encoding/decoding routines ===================================== }
procedure LbDecodeBase64A(InStream, OutStream : TStream);
var
  I, O, Count, c1, c2, c3 : Byte;
  InBuf  : array[0..87] of Byte;
  OutBuf : array[0..65] of Byte;
begin
  repeat
    O := 0;
    I := 0;

    Count := InStream.Read(InBuf, SizeOf(InBuf));
    if (Count = 0) then
      Break;

    { Decode data to output stream }
    while I < Count do begin
      if (InBuf[I] < 43) or (InBuf[I] > 122) or
         (InBuf[I+1] < 43) or (InBuf[I+1] > 122) or
         (InBuf[I+2] < 43) or (InBuf[I+2] > 122) or
         (InBuf[I+3] < 43) or (InBuf[I+3] > 122) then
        raise Exception.Create('Invalid Base64 Character');

      c1 := LbD64Table[InBuf[I]];
      c2 := LbD64Table[InBuf[I+1]];
      c3 := LbD64Table[InBuf[I+2]];
      OutBuf[O] := ((c1 shl 2) or (c2 shr 4));
      Inc(O);
      if Char(InBuf[I+2]) <> '=' then begin
        OutBuf[O] := ((c2 shl 4) or (c3 shr 2));
        Inc(O);
        if Char(InBuf[I+3]) <> '=' then begin
          OutBuf[O] := ((c3 shl 6) or LbD64Table[InBuf[I+3]]);
          Inc(O);
        end;
      end;
      Inc(I, 4);
    end;
    OutStream.Write(OutBuf, O);
  until Count < SizeOf(InBuf) div SizeOf(AnsiChar);
end;

procedure LbDecodeBase64W(InStream, OutStream : TStream);
var
  I, O, Count, c1, c2, c3 : Byte;
  InBuf  : array[0..87] of Word;
  OutBuf : array[0..65] of Byte;
begin
  repeat
    O := 0;
    I := 0;

    Count := InStream.Read(InBuf, SizeOf(InBuf)) div 2;
    if (Count = 0) then
      Break;

    { Decode data to output stream }
    while I < Count do begin
      if (InBuf[I] < 43) or (InBuf[I] > 122) or
         (InBuf[I+1] < 43) or (InBuf[I+1] > 122) or
         (InBuf[I+2] < 43) or (InBuf[I+2] > 122) or
         (InBuf[I+3] < 43) or (InBuf[I+3] > 122) then
        raise Exception.Create('Invalid Base64 Character');

      c1 := LbD64Table[InBuf[I]];
      c2 := LbD64Table[InBuf[I+1]];
      c3 := LbD64Table[InBuf[I+2]];
      OutBuf[O] := ((c1 shl 2) or (c2 shr 4));
      Inc(O);
      if Char(InBuf[I+2]) <> '=' then begin
        OutBuf[O] := ((c2 shl 4) or (c3 shr 2));
        Inc(O);
        if Char(InBuf[I+3]) <> '=' then begin
          OutBuf[O] := ((c3 shl 6) or LbD64Table[InBuf[I+3]]);
          Inc(O);
        end;
      end;
      Inc(I, 4);
    end;
    OutStream.Write(OutBuf, O);
  until Count < SizeOf(InBuf) div SizeOf(Char);
end;
{ -------------------------------------------------------------------------- }
procedure LbEncodeBase64A(InStream, OutStream : TStream);
var
  I, O, Count : Integer;
  InBuf  : array[1..45] of Byte;
  OutBuf : array[0..62] of AnsiChar;
  Temp : Byte;
begin
  FillChar(OutBuf, Sizeof(OutBuf), #0);

  repeat
    Count := InStream.Read(InBuf, SizeOf(InBuf));
    if Count = 0 then Break;
    I := 1;
    O := 0;
    while I <= (Count-2) do begin
      { Encode 1st byte }
      Temp := (InBuf[I] shr 2);
      OutBuf[O] := AnsiChar(Lb64Table[Temp and $3F]);

      { Encode 1st/2nd byte }
      Temp := (InBuf[I] shl 4) or (InBuf[I+1] shr 4);
      OutBuf[O+1] := AnsiChar(Lb64Table[Temp and $3F]);

      { Encode 2nd/3rd byte }
      Temp := (InBuf[I+1] shl 2) or (InBuf[I+2] shr 6);
      OutBuf[O+2] := AnsiChar(Lb64Table[Temp and $3F]);

      { Encode 3rd byte }
      Temp := (InBuf[I+2] and $3F);
      OutBuf[O+3] := AnsiChar(Lb64Table[Temp]);

      Inc(I, 3);
      Inc(O, 4);
    end;

    { Are there odd bytes to add? }
    if (I <= Count) then begin
      Temp := (InBuf[I] shr 2);
      OutBuf[O] := AnsiChar(Lb64Table[Temp and $3F]);

      { One odd byte }
      if I = Count then begin
        Temp := (InBuf[I] shl 4) and $30;
        OutBuf[O+1] := AnsiChar(Lb64Table[Temp and $3F]);
        OutBuf[O+2] := '=';
      { Two odd bytes }
      end else begin
        Temp := ((InBuf[I] shl 4) and $30) or ((InBuf[I+1] shr 4) and $0F);
        OutBuf[O+1] := AnsiChar(Lb64Table[Temp and $3F]);
        Temp := (InBuf[I+1] shl 2) and $3C;
        OutBuf[O+2] := AnsiChar(Lb64Table[Temp and $3F]);
      end;
      { Add padding }
      OutBuf[O+3] := '=';
      Inc(O, 4);
    end;

    { Write encoded block to stream }
    OutStream.Write(OutBuf, O * SizeOf(AnsiChar));
  until Count < SizeOf(InBuf);
end;


procedure LbEncodeBase64W(InStream, OutStream : TStream);
var
  I, O, Count : Integer;
  InBuf  : array[1..45] of Byte;
  OutBuf : array[0..62] of WideChar;
  Temp : Byte;
begin
  FillChar(OutBuf, Sizeof(OutBuf), #0);

  repeat
    Count := InStream.Read(InBuf, SizeOf(InBuf));
    if Count = 0 then Break;
    I := 1;
    O := 0;
    while I <= (Count-2) do begin
      { Encode 1st byte }
      Temp := (InBuf[I] shr 2);
      OutBuf[O] := WideChar(Lb64Table[Temp and $3F]);

      { Encode 1st/2nd byte }
      Temp := (InBuf[I] shl 4) or (InBuf[I+1] shr 4);
      OutBuf[O+1] := WideChar(Lb64Table[Temp and $3F]);

      { Encode 2nd/3rd byte }
      Temp := (InBuf[I+1] shl 2) or (InBuf[I+2] shr 6);
      OutBuf[O+2] := WideChar(Lb64Table[Temp and $3F]);

      { Encode 3rd byte }
      Temp := (InBuf[I+2] and $3F);
      OutBuf[O+3] := WideChar(Lb64Table[Temp]);

      Inc(I, 3);
      Inc(O, 4);
    end;

    { Are there odd bytes to add? }
    if (I <= Count) then begin
      Temp := (InBuf[I] shr 2);
      OutBuf[O] := WideChar(Lb64Table[Temp and $3F]);

      { One odd byte }
      if I = Count then begin
        Temp := (InBuf[I] shl 4) and $30;
        OutBuf[O+1] := WideChar(Lb64Table[Temp and $3F]);
        OutBuf[O+2] := '=';
      { Two odd bytes }
      end else begin
        Temp := ((InBuf[I] shl 4) and $30) or ((InBuf[I+1] shr 4) and $0F);
        OutBuf[O+1] := WideChar(Lb64Table[Temp and $3F]);
        Temp := (InBuf[I+1] shl 2) and $3C;
        OutBuf[O+2] := WideChar(Lb64Table[Temp and $3F]);
      end;
      { Add padding }
      OutBuf[O+3] := '=';
      Inc(O, 4);
    end;

    { Write encoded block to stream }
    OutStream.Write(OutBuf, O * SizeOf(Char));
  until Count < SizeOf(InBuf);
end;


{ == Blowfish string encryption/decryption ================================= }
function BFEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := BFEncryptStringExW(InString, Key, Encrypt);
  {$ELSE}
  Result := BFEncryptStringExA(InString, Key, Encrypt);
  {$ENDIF}
end;

function BFEncryptStringExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
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
    BFEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    BFEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

{$IFDEF UNICODE}
function BFEncryptStringExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
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
    BFEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    BFEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

{ -------------------------------------------------------------------------- }
function BFEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := BFEncryptStringCBCExW(InString, Key, Encrypt);
  {$ELSE}
  Result := BFEncryptStringCBCExA(InString, Key, Encrypt);
  {$ENDIF}
end;

function BFEncryptStringCBCExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
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
    BFEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    BFEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

{$IFDEF UNICODE}
function BFEncryptStringCBCExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
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
    BFEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    BFEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure BFEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := BFEncryptStringEx(InString, Key, Encrypt);
end;

procedure BFEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := BFEncryptStringExA(InString, Key, Encrypt);
end;

{$IFDEF UNICODE}
procedure BFEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := BFEncryptStringExW(InString, Key, Encrypt);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure BFEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := BFEncryptStringCBCEx(InString, Key, Encrypt);
end;

procedure BFEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := BFEncryptStringCBCExA(InString, Key, Encrypt);
end;

{$IFDEF UNICODE}
procedure BFEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := BFEncryptStringCBCExW(InString, Key, Encrypt);
end;
{$ENDIF}


{ == DES string encryption/decryption ====================================== }
function DESEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := DESEncryptStringExW(InString, Key, Encrypt);
  {$ELSE}
  Result := DESEncryptStringExA(InString, Key, Encrypt);
  {$ENDIF}
end;

{$IFDEF UNICODE}
function DESEncryptStringExW(const InString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean) : UnicodeString;
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
    DESEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    DESEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

function DESEncryptStringExA(const InString : AnsiString;
            const Key : TKey64; Encrypt : Boolean) : AnsiString;
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
    DESEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    DESEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{ -------------------------------------------------------------------------- }
function DESEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := DESEncryptStringCBCExW(InString, Key, Encrypt);
  {$ELSE}
  Result := DESEncryptStringCBCExA(InString, Key, Encrypt);
  {$ENDIF}
end;

{$IFDEF UNICODE}
function DESEncryptStringCBCExW(const InString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean) : UnicodeString;
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
    DESEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    DESEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

function DESEncryptStringCBCExA(const InString : AnsiString;
            const Key : TKey64; Encrypt : Boolean) : AnsiString;
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
    DESEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    DESEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{ -------------------------------------------------------------------------- }
procedure DESEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean);
begin
  OutString := DESEncryptStringEx(InString, Key, Encrypt);
end;

procedure DESEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey64; Encrypt : Boolean);
begin
  OutString := DESEncryptStringExA(InString, Key, Encrypt);
end;

{$IFDEF UNICODE}
procedure DESEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean);
begin
  OutString := DESEncryptStringExW(InString, Key, Encrypt);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure DESEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey64; Encrypt : Boolean);
begin
  OutString := DESEncryptStringCBCEx(InString, Key, Encrypt);
end;

procedure DESEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey64; Encrypt : Boolean);
begin
  OutString := DESEncryptStringCBCExA(InString, Key, Encrypt);
end;

{$IFDEF UNICODE}
procedure DESEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey64; Encrypt : Boolean);
begin
  OutString := DESEncryptStringCBCExW(InString, Key, Encrypt);
end;
{$ENDIF}


{ == TripleDES string encryption/decryption ================================ }
function TripleDESEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := TripleDESEncryptStringExW(InString, Key, Encrypt);
  {$ELSE}
  Result := TripleDESEncryptStringExA(InString, Key, Encrypt);
  {$ENDIF}
end;

{$IFDEF UNICODE}
function TripleDESEncryptStringExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
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
    TripleDESEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    TripleDESEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

function TripleDESEncryptStringExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
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
    TripleDESEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    TripleDESEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{ -------------------------------------------------------------------------- }
function TripleDESEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := TripleDESEncryptStringCBCExW(InString, Key, Encrypt);
  {$ELSE}
  Result := TripleDESEncryptStringCBCExA(InString, Key, Encrypt);
  {$ENDIF}
end;

{$IFDEF UNICODE}
function TripleDESEncryptStringCBCExW(const InString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean) : UnicodeString;
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
    TripleDESEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    TripleDESEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

function TripleDESEncryptStringCBCExA(const InString : AnsiString;
            const Key : TKey128; Encrypt : Boolean) : AnsiString;
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
    TripleDESEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    TripleDESEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{ -------------------------------------------------------------------------- }
procedure TripleDESEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := TripleDESEncryptStringEx(InString, Key, Encrypt);
end;

procedure TripleDESEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := TripleDESEncryptStringExA(InString, Key, Encrypt);
end;

{$IFDEF UNICODE}
procedure TripleDESEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := TripleDESEncryptStringExW(InString, Key, Encrypt);
end;
{$ENDIF}
{ -------------------------------------------------------------------------- }
procedure TripleDESEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := TripleDESEncryptStringCBCEx(InString, Key, Encrypt);
end;

procedure TripleDESEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := TripleDESEncryptStringCBCExA(InString, Key, Encrypt);
end;

{$IFDEF UNICODE}
procedure TripleDESEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key : TKey128; Encrypt : Boolean);
begin
  OutString := TripleDESEncryptStringCBCExW(InString, Key, Encrypt);
end;
{$ENDIF}

{ == Rijndael string encryption/decryption ================================== }
function RDLEncryptStringEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := RDLEncryptStringExW(InString, Key, KeySize, Encrypt);
  {$ELSE}
  Result := RDLEncryptStringExA(InString, Key, KeySize, Encrypt);
  {$ENDIF}
end;

{$IFDEF UNICODE}
function RDLEncryptStringExW(const InString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean) : UnicodeString;
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
    RDLEncryptStream(InStream, WorkStream, Key, KeySize, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    RDLEncryptStream(WorkStream, OutStream, Key, KeySize, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

function RDLEncryptStringExA(const InString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean) : AnsiString;
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
    RDLEncryptStream(InStream, WorkStream, Key, KeySize, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    RDLEncryptStream(WorkStream, OutStream, Key, KeySize, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{ -------------------------------------------------------------------------- }
function RDLEncryptStringCBCEx(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean) : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  {$IFDEF LOCKBOXUNICODE}
  Result := RDLEncryptStringCBCExW(InString, Key, KeySize, Encrypt);
  {$ELSE}
  Result := RDLEncryptStringCBCExA(InString, Key, KeySize, Encrypt);
  {$ENDIF}
end;

{$IFDEF UNICODE}
function RDLEncryptStringCBCExW(const InString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean) : UnicodeString;
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
    RDLEncryptStreamCBC(InStream, WorkStream, Key, KeySize, True);
    WorkStream.Position := 0;
    LbEncodeBase64W(WorkStream, OutStream);
  end else begin
    LbDecodeBase64W(InStream, WorkStream);
    WorkStream.Position := 0;
    RDLEncryptStreamCBC(WorkStream, OutStream, Key, KeySize, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(WideChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{$ENDIF}

function RDLEncryptStringCBCExA(const InString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean) : AnsiString;
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
    RDLEncryptStreamCBC(InStream, WorkStream, Key, KeySize, True);
    WorkStream.Position := 0;
    LbEncodeBase64A(WorkStream, OutStream);
  end else begin
    LbDecodeBase64A(InStream, WorkStream);
    WorkStream.Position := 0;
    RDLEncryptStreamCBC(WorkStream, OutStream, Key, KeySize, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size div SizeOf(AnsiChar));
  OutStream.Read(Result[1], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;
{ -------------------------------------------------------------------------- }
procedure RDLEncryptString(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean);
begin
  OutString := RDLEncryptStringEx(InString, Key, KeySize, Encrypt);
end;

procedure RDLEncryptStringA(const InString : AnsiString; var OutString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean);
begin
  OutString := RDLEncryptStringExA(InString, Key, KeySize, Encrypt);
end;

{$IFDEF UNICODE}
procedure RDLEncryptStringW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean);
begin
  OutString := RDLEncryptStringExW(InString, Key, KeySize, Encrypt);
end;
{$ENDIF}

{ -------------------------------------------------------------------------- }
procedure RDLEncryptStringCBC(const InString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}; var OutString : {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
            const Key; KeySize : Longint; Encrypt : Boolean);
begin
  OutString := RDLEncryptStringCBCEx(InString, Key, KeySize, Encrypt);
end;

procedure RDLEncryptStringCBCA(const InString : AnsiString; var OutString : AnsiString;
            const Key; KeySize : Longint; Encrypt : Boolean);
begin
  OutString := RDLEncryptStringCBCExA(InString, Key, KeySize, Encrypt);
end;

{$IFDEF UNICODE}
procedure RDLEncryptStringCBCW(const InString : UnicodeString; var OutString : UnicodeString;
            const Key; KeySize : Longint; Encrypt : Boolean);
begin
  OutString := RDLEncryptStringCBCExW(InString, Key, KeySize, Encrypt);
end;
{$ENDIF}


end.
