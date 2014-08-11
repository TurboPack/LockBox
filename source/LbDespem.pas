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
{*                   LBDESPEM.PAS 2.07                   *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I lockbox.inc}

unit LbDESPEM;
  {-RFC-1423 padding compliant DES and 3-key TripleDES }

interface

uses

{$IFDEF MSWINDOWS}
  Windows,
  MMSystem,
{$ENDIF}
{$IFDEF LINUX}
  Libc,
{$ENDIF}
  Classes,
  SysUtils,
  LbCipher;

type
  ECipherException = class(Exception);

{ high level encryption routines }
procedure DESEncryptFileCBCPEM(const InFile, OutFile : string;
            const Key : TKey64; const IV : TDESBlock; Encrypt : Boolean);
procedure DESEncryptStreamCBCPEM(InStream, OutStream : TStream;
            const Key : TKey64; const IV : TDESBlock; Encrypt : Boolean);
procedure TripleDESEncryptFileCBCPEM(const InFile, OutFile : string;
            const Key1, Key2, Key3 : TKey64; const IV : TDESBlock;
            Encrypt : Boolean);
procedure TripleDESEncryptStreamCBCPEM(InStream, OutStream : TStream;
            const Key1, Key2, Key3 : TKey64; const IV : TDESBlock;
            Encrypt : Boolean);

implementation

const
  SInvalidFileFormat = 'Invalid file format';


{ == DES =================================================================== }
procedure DESEncryptFileCBCPEM(const InFile, OutFile : string;
            const Key : TKey64; const IV : TDESBlock; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      DESEncryptStreamCBCPEM(InStream, OutStream, Key, IV, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure DESEncryptStreamCBCPEM(InStream, OutStream : TStream;
            const Key : TKey64; const IV : TDESBlock; Encrypt : Boolean);
var
  i          : Longint;
  Block      : TDESBlock;
  PrevBlock  : TDESBlock;
  Work       : TDESBlock;
  Context    : TDESContext;
  BlockCount : LongInt;
  PadCount   : Byte;
  OddCount   : Byte;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
begin
  InitEncryptDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));
  OddCount := InStream.Size mod SizeOf(Block);

  { get number of bytes to pad at the end }
  if (OddCount > 0) then begin
    if not Encrypt then
      raise ECipherException.Create(SInvalidFileFormat);
    PadCount := SizeOf(Block) - OddCount;
    Inc(BlockCount);
  end else
    PadCount := 0;

  { initialization vector }
  PrevBlock := IV;

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    InStream.Read(Block, SizeOf(Block));
    if Encrypt then begin
      EncryptDESCBC(Context, PrevBlock, Block);
      PrevBlock := Block;
    end else begin
      Work := Block;
      EncryptDESCBC(Context, PrevBlock, Block);
      PrevBlock := Work;
    end;
    OutStream.Write(Block, SizeOf(Block));
  end;

  { process the last block }
  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);
    InStream.Read(Block, OddCount);
    { pad the remaining bytes in the block }
    if (OddCount > 0) then
      for i := OddCount to SizeOf(Block) - 1 do
        Block[i] := PadCount;
    {encrypt and save full block}
    EncryptDESCBC(Context, PrevBlock, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    InStream.Read(Block, SizeOf(Block));
    EncryptDESCBC(Context, PrevBlock, Block);
    OutStream.Write(Block, SizeOf(Block));
  end;
end;


{ == Triple DES ============================================================ }
procedure TripleDESEncryptFileCBCPEM(const InFile, OutFile : string;
            const Key1, Key2, Key3 : TKey64; const IV : TDESBlock;
            Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      TripleDESEncryptStreamCBCPEM(InStream, OutStream, Key1, Key2, Key3, IV, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TripleDESEncryptStreamCBCPEM(InStream, OutStream : TStream;
            const Key1, Key2, Key3 : TKey64; const IV : TDESBlock;
            Encrypt : Boolean);
var
  i          : LongInt;
  Block      : TDESBlock;
  PrevBlock  : TDESBlock;
  Work       : TDESBlock;
  Context    : TTripleDESContext3Key;
  BlockCount : LongInt;
  PadCount   : Byte;
  OddCount   : Byte;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
begin
  InitEncryptTripleDES3Key(Key1, Key2, Key3, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));
  OddCount := InStream.Size mod SizeOf(Block);

  { get number of bytes to pad at the end }
  if (OddCount > 0) then begin
    if not Encrypt then
      raise Exception.Create('Invalid Ciphertext block format');
    PadCount := SizeOf(Block) - OddCount;
    Inc(BlockCount);
  end else
    PadCount := 0;

  { initialization vector }
  PrevBlock := IV;

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    InStream.Read(Block, SizeOf(Block));
    if Encrypt then begin
      EncryptTripleDESCBC3Key(Context, PrevBlock, Block);
      PrevBlock := Block;
    end else begin
      Work := Block;
      EncryptTripleDESCBC3Key(Context, PrevBlock, Block);
      PrevBlock := Work;
    end;
    OutStream.Write(Block, SizeOf(Block));
  end;

  { process the last block }
  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);
    InStream.Read(Block, OddCount);
    { pad the remaining bytes in the block }
    if (OddCount > 0) then
      for i := OddCount to SizeOf(Block) - 1 do
        Block[i] := PadCount;
    {encrypt and save full block}
    EncryptTripleDESCBC3Key(Context, PrevBlock, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    InStream.Read(Block, SizeOf(Block));
    EncryptTripleDESCBC3Key(Context, PrevBlock, Block);
    OutStream.Write(Block, SizeOf(Block));
  end;
end;

end.