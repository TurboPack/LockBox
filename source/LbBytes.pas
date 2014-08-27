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
 *                 Roman Kassebaum
 *
 * ***** END LICENSE BLOCK ***** *)
{*********************************************************}
{*                   LBBYTES.PAS 2.08                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

unit LbBytes;
  {-string encryption routines}

interface

uses
  Classes, SysUtils, LbCipher, LbProc;

type
  TBlowfishBytes = class(TBlowfishEncrypt)
  public
    class procedure BFEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean); static;
    class procedure BFEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean); static;
    class function BFEncryptBytesCBCEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes; static;
    class function BFEncryptBytesEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes; static;
  end;

  TDESBytes = class(TDESEncrypt)
  public
    class procedure DESEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey64; Encrypt: Boolean); static;
    class procedure DESEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey64; Encrypt: Boolean); static;
    class function DESEncryptBytesCBCEx(const InBytes: TBytes; const Key: TKey64; Encrypt: Boolean): TBytes; static;
    class function DESEncryptBytesEx(const InBytes: TBytes; const Key: TKey64; Encrypt: Boolean): TBytes; static;
    class procedure TripleDESEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean); static;
    class procedure TripleDESEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean); static;
    class function TripleDESEncryptBytesCBCEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes; static;
    class function TripleDESEncryptBytesEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes; static;
  end;

  TRDLBytes = class(TRDLEncrypt)
  public
    class procedure RDLEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean); static;
    class procedure RDLEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean); static;
    class function RDLEncryptBytesCBCEx(const InBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean): TBytes; static;
    class function RDLEncryptBytesEx(const InBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean): TBytes; static;
  end;

  TLbBase64 = record
  strict private const
    Lb64Table : array[0..63] of Byte = ( 65, 66, 67, 68, 69,
           70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
           80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
           90, 97, 98, 99, 100, 101, 102, 103, 104, 105,
          106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
          116, 117, 118, 119, 120, 121, 122, 48, 49, 50,
           51, 52, 53, 54, 55, 56, 57, 43, 47);
    LbD64Table : array[43..122] of Byte = ($3E, $7F, $7F, $7F, $3F, $34,
        $35, $36, $37, $38, $39, $3A, $3B, $3C, $3D, $7F, $7F, $7F, $7F,
        $7F, $7F, $7F, $00, $01, $02, $03, $04, $05, $06, $07, $08, $09,
        $0A, $0B, $0C, $0D, $0E, $0F, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $7F, $7F, $7F, $7F, $7F, $7F, $1A, $1B, $1C, $1D,
        $1E, $1F, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $2A,
        $2B, $2C, $2D, $2E, $2F, $30, $31, $32, $33);
  public
    class procedure LbDecodeBase64(InStream, OutStream : TStream); static;
    class procedure LbEncodeBase64(InStream, OutStream : TStream); static;
  end;

implementation

{ TBlowfishBytes }

class procedure TBlowfishBytes.BFEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean);
begin
  OutBytes := BFEncryptBytesEx(InBytes, Key, Encrypt);
end;

class procedure TBlowfishBytes.BFEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean);
begin
  OutBytes := BFEncryptBytesCBCEx(InBytes, Key, Encrypt);
end;

class function TBlowfishBytes.BFEncryptBytesCBCEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes;
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
    BFEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    BFEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class function TBlowfishBytes.BFEncryptBytesEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes;
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
    BFEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    BFEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class procedure TDESBytes.DESEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey64; Encrypt: Boolean);
begin
  OutBytes := DESEncryptBytesEx(InBytes, Key, Encrypt);
end;

class procedure TDESBytes.DESEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey64; Encrypt: Boolean);
begin
  OutBytes := DESEncryptBytesCBCEx(InBytes, Key, Encrypt);
end;

{ TDESBytes }

class function TDESBytes.DESEncryptBytesCBCEx(const InBytes: TBytes; const Key: TKey64; Encrypt: Boolean): TBytes;
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
    DESEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    DESEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class function TDESBytes.DESEncryptBytesEx(const InBytes: TBytes; const Key: TKey64; Encrypt: Boolean): TBytes;
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
    DESEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    DESEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class procedure TDESBytes.TripleDESEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean);
begin
  OutBytes := TripleDESEncryptBytesEx(InBytes, Key, Encrypt);
end;

class procedure TDESBytes.TripleDESEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key: TKey128; Encrypt: Boolean);
begin
  OutBytes := TripleDESEncryptBytesCBCEx(InBytes, Key, Encrypt);
end;

class function TDESBytes.TripleDESEncryptBytesCBCEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes;
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
    TripleDESEncryptStreamCBC(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    TripleDESEncryptStreamCBC(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class function TDESBytes.TripleDESEncryptBytesEx(const InBytes: TBytes; const Key: TKey128; Encrypt: Boolean): TBytes;
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
    TripleDESEncryptStream(InStream, WorkStream, Key, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    TripleDESEncryptStream(WorkStream, OutStream, Key, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

{ TRDLBytes }

class procedure TRDLBytes.RDLEncryptBytes(const InBytes: TBytes; var OutBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean);
begin
  OutBytes := RDLEncryptBytesEx(InBytes, Key, KeySize, Encrypt);
end;

class procedure TRDLBytes.RDLEncryptBytesCBC(const InBytes: TBytes; var OutBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean);
begin
  OutBytes := RDLEncryptBytesCBCEx(InBytes, Key, KeySize, Encrypt);
end;

class function TRDLBytes.RDLEncryptBytesCBCEx(const InBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean): TBytes;
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
    RDLEncryptStreamCBC(InStream, WorkStream, Key, KeySize, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    RDLEncryptStreamCBC(WorkStream, OutStream, Key, KeySize, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

class function TRDLBytes.RDLEncryptBytesEx(const InBytes: TBytes; const Key; KeySize: Longint; Encrypt: Boolean): TBytes;
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
    RDLEncryptStream(InStream, WorkStream, Key, KeySize, True);
    WorkStream.Position := 0;
    TLbBase64.LbEncodeBase64(WorkStream, OutStream);
  end else begin
    TLbBase64.LbDecodeBase64(InStream, WorkStream);
    WorkStream.Position := 0;
    RDLEncryptStream(WorkStream, OutStream, Key, KeySize, False);
  end;
  OutStream.Position := 0;
  SetLength(Result, OutStream.Size);
  OutStream.Read(Result[0], OutStream.Size);

  InStream.Free;
  OutStream.Free;
  WorkStream.Free;
end;

{ TLbBase64 }

class procedure TLbBase64.LbDecodeBase64(InStream, OutStream : TStream);
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
  until Count < SizeOf(InBuf);
end;

class procedure TLbBase64.LbEncodeBase64(InStream, OutStream : TStream);
var
  I, O, Count : Integer;
  InBuf  : array[1..45] of Byte;
  OutBuf : array[0..62] of Byte;
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
      OutBuf[O] := Lb64Table[Temp and $3F];

      { Encode 1st/2nd byte }
      Temp := (InBuf[I] shl 4) or (InBuf[I+1] shr 4);
      OutBuf[O+1] := Lb64Table[Temp and $3F];

      { Encode 2nd/3rd byte }
      Temp := (InBuf[I+1] shl 2) or (InBuf[I+2] shr 6);
      OutBuf[O+2] := Lb64Table[Temp and $3F];

      { Encode 3rd byte }
      Temp := (InBuf[I+2] and $3F);
      OutBuf[O+3] := Lb64Table[Temp];

      Inc(I, 3);
      Inc(O, 4);
    end;

    { Are there odd bytes to add? }
    if (I <= Count) then begin
      Temp := (InBuf[I] shr 2);
      OutBuf[O] := Lb64Table[Temp and $3F];

      { One odd byte }
      if I = Count then begin
        Temp := (InBuf[I] shl 4) and $30;
        OutBuf[O+1] := Lb64Table[Temp and $3F];
        OutBuf[O+2] := Ord('=');
      { Two odd bytes }
      end else begin
        Temp := ((InBuf[I] shl 4) and $30) or ((InBuf[I+1] shr 4) and $0F);
        OutBuf[O+1] := Lb64Table[Temp and $3F];
        Temp := (InBuf[I+1] shl 2) and $3C;
        OutBuf[O+2] := Lb64Table[Temp and $3F];
      end;
      { Add padding }
      OutBuf[O+3] := Ord('=');
      Inc(O, 4);
    end;

    { Write encoded block to stream }
    OutStream.Write(OutBuf, O);
  until Count < SizeOf(InBuf);
end;

end.
