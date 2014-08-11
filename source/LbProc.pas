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
{*                   LBPROC.PAS 2.08                     *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbProc;
  {-stream and file routines for block and stream ciphers}

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

type                                                                            {!!.06a}
  TProgressProc = procedure(CurPostion, TotalSize: longint);                    {!!.06a}

var                                                                             {!!.06a}
  LbOnProgress : TProgressProc;                                                 {!!.06a}
  LbProgressSize: Longint;                                                      {!!.06a}

{ high level encryption routines }
procedure BFEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean); 
procedure BFEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean); 
procedure BFEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean); 
procedure BFEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean); 
procedure DESEncryptFile(const InFile, OutFile : string;
            const Key : TKey64; Encrypt : Boolean); 
procedure DESEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey64; Encrypt : Boolean); 
procedure DESEncryptStream(InStream, OutStream : TStream;
            const Key : TKey64; Encrypt : Boolean); 
procedure DESEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey64; Encrypt : Boolean); 
procedure LBCEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean); 
procedure LBCEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean); 
procedure LBCEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean); 
procedure LBCEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean); 
procedure LQCEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean); 
procedure LQCEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean); 
procedure LQCEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean); 
procedure LQCEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean); 
procedure LSCEncryptFile(const InFile, OutFile : string;
            const Key; KeySize : Integer); 
procedure RNG32EncryptFile(const InFile, OutFile : string;
            Key : LongInt); 
procedure RNG64EncryptFile(const InFile, OutFile : string;
            KeyHi, KeyLo : LongInt); 
procedure TripleDESEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean); 
procedure TripleDESEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean); 
procedure TripleDESEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean); 
procedure TripleDESEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean); 
procedure RDLEncryptFile(const InFile, OutFile : string;
            const Key; KeySize : Longint; Encrypt : Boolean);
procedure RDLEncryptFileCBC(const InFile, OutFile : string;
            const Key; KeySize : Longint; Encrypt : Boolean);
procedure RDLEncryptStream(InStream, OutStream : TStream;
            const Key; KeySize : Longint; Encrypt : Boolean);
procedure RDLEncryptStreamCBC(InStream, OutStream : TStream;
            const Key; KeySize : Longint; Encrypt : Boolean);

{ high level hashing routines }
procedure FileHashMD5(var Digest : TMD5Digest; const AFileName : string);
procedure StreamHashMD5(var Digest : TMD5Digest; AStream : TStream);
procedure FileHashSHA1(var Digest : TSHA1Digest; const AFileName : string);
procedure StreamHashSHA1(var Digest : TSHA1Digest; AStream : TStream);


implementation

const
  SInvalidFileFormat = 'Invalid file format';


{ == Blowfish ============================================================== }
procedure BFEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      BFEncryptStream(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure BFEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      BFEncryptStreamCBC(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure BFEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TBFBlock;
  Context    : TBFContext;
  BlockCount : LongInt;
begin
  InitEncryptBF(Key, Context);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptBF(Context, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptBF(Context, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptBF(Context, Block, Encrypt);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;
{ -------------------------------------------------------------------------- }
procedure BFEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean);
var
  I : LongInt;
  Block : TBFBlock;
  IV : TBFBlock;
  Work : TBFBlock;
  Context : TBFContext;
  BlockCount : LongInt;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  InitEncryptBF(Key, Context);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
{$IFDEF MSWINDOWS}
    Block[0] := timeGetTime;
    Block[1] := timeGetTime;
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @Block[0], SizeOf( byte ), SizeOf( Block[0] ), fd );
    fread( @Block[1], SizeOf( byte ), SizeOf( Block[1] ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
  FS := TFileStream.Create('/dev/random', fmOpenRead);
  try
    FS.Read(Block[0], SizeOf(Block[0]));
    FS.Read(Block[1], SizeOf(Block[1]));
  finally
    FS.Free;
  end;
{$ENDIF}
    EncryptBF(Context, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));
    IV := Block;
  end else begin
    {read the frist block to prime the IV}
    InStream.Read(Block, SizeOf(Block));
    Dec(BlockCount);
    IV := Block;
  end;

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);

    if Encrypt then begin
      EncryptBFCBC(Context, IV, Block, Encrypt);
      IV := Block;
    end else begin
      Work := Block;
      EncryptBFCBC(Context, IV, Block, Encrypt);
      IV := Work;
    end;

    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptBFCBC(Context, IV, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptBFCBC(Context, IV, Block, Encrypt);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;


{ == DES =================================================================== }
procedure DESEncryptFile(const InFile, OutFile : string;
            const Key : TKey64; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      DESEncryptStream(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure DESEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey64; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      DESEncryptStreamCBC(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure DESEncryptStream(InStream, OutStream : TStream;
            const Key : TKey64; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TDESBlock;
  Context    : TDESContext;
  BlockCount : LongInt;
begin
  InitEncryptDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptDES(Context, Block);
    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptDES(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptDES(Context, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;
{ -------------------------------------------------------------------------- }
procedure DESEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey64; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TDESBlock;
  IV         : TDESBlock;
  Work       : TDESBlock;
  Context    : TDESContext;
  BlockCount : LongInt;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  InitEncryptDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
{$IFDEF MSWINDOWS}
    Block[0] := timeGetTime;
    Block[1] := timeGetTime;
    Block[2] := timeGetTime;
    Block[3] := timeGetTime;
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @Block[0], SizeOf( byte ), SizeOf( Block[0] ), fd );
    fread( @Block[1], SizeOf( byte ), SizeOf( Block[1] ), fd );
    fread( @Block[2], SizeOf( byte ), SizeOf( Block[2] ), fd );
    fread( @Block[3], SizeOf( byte ), SizeOf( Block[3] ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
  FS := TFileStream.Create('/dev/random', fmOpenRead);
  try
    FS.Read(Block[0], SizeOf(Block[0]));
    FS.Read(Block[1], SizeOf(Block[1]));
    FS.Read(Block[2], SizeOf(Block[2]));
    FS.Read(Block[3], SizeOf(Block[3]));
  finally
    FS.Free;
  end;
{$ENDIF}
    EncryptDES(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
    IV := Block;
  end else begin
    {read the frist block to prime the IV}
    InStream.Read(Block, SizeOf(Block));
    Dec(BlockCount);
    IV := Block;
  end;

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);

    if Encrypt then begin
      EncryptDESCBC(Context, IV, Block);
      IV := Block;
    end else begin
      Work := Block;
      EncryptDESCBC(Context, IV, Block);
      IV := Work;
    end;

    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptDESCBC(Context, IV, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptDESCBC(Context, IV, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;


{ == LockBox Cipher ======================================================== }
procedure LBCEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      LBCEncryptStream(InStream, OutStream, Key, Rounds, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure LBCEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      LBCEncryptStreamCBC(InStream, OutStream, Key, Rounds, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure LBCEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TLBCBlock;
  Context    : TLBCContext;
  BlockCount : LongInt;
begin
  InitEncryptLBC(Key, Context, Rounds, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptLBC(Context, Block);
    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptLBC(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptLBC(Context, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;
{ -------------------------------------------------------------------------- }
procedure LBCEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Rounds : LongInt; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TLBCBlock;
  IV         : TLBCBlock;
  Work       : TLBCBlock;
  Context    : TLBCContext;
  BlockCount : LongInt;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  InitEncryptLBC(Key, Context, Rounds, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
{$IFDEF MSWINDOWS}
    Block[0] := timeGetTime;
    Block[1] := timeGetTime;
    Block[2] := timeGetTime;
    Block[3] := timeGetTime;
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @Block[0], SizeOf( byte ), SizeOf( Block[0] ), fd );
    fread( @Block[1], SizeOf( byte ), SizeOf( Block[1] ), fd );
    fread( @Block[2], SizeOf( byte ), SizeOf( Block[2] ), fd );
    fread( @Block[3], SizeOf( byte ), SizeOf( Block[3] ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
    FS := TFileStream.Create('/dev/random', fmOpenRead);
    try
      FS.Read(Block[0], SizeOf(Block[0]));
      FS.Read(Block[1], SizeOf(Block[1]));
      FS.Read(Block[2], SizeOf(Block[2]));
      FS.Read(Block[3], SizeOf(Block[3]));
    finally
      FS.Free;
    end;
{$ENDIF}
    EncryptLBC(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
    IV := Block;
  end else begin
    {read the frist block to prime the IV}
    InStream.Read(Block, SizeOf(Block));
    Dec(BlockCount);
    IV := Block;
  end;

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);

    if Encrypt then begin
      EncryptLBCCBC(Context, IV, Block);
      IV := Block;
    end else begin
      Work := Block;
      EncryptLBCCBC(Context, IV, Block);
      IV := Work;
    end;

    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptLBCCBC(Context, IV, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptLBCCBC(Context, IV, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;


{ == LockBox Quick Cipher (LQC) ============================================ }
procedure LQCEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      LQCEncryptStream(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure LQCEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      LQCEncryptStreamCBC(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure LQCEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TLQCBlock;
  BlockCount : LongInt;
begin
  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptLQC(Key, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptLQC(Key, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptLQC(Key, Block, Encrypt);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;
{ -------------------------------------------------------------------------- }
procedure LQCEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TLQCBlock;
  IV         : TLQCBlock;
  Work       : TLQCBlock;
  BlockCount : LongInt;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
{$IFDEF MSWINDOWS}
    Block[0] := timeGetTime;
    Block[1] := timeGetTime;
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @Block[0], SizeOf( byte ), SizeOf( Block[0] ), fd );
    fread( @Block[1], SizeOf( byte ), SizeOf( Block[1] ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
    FS := TFileStream.Create('/dev/random', fmOpenRead);
    try
      FS.Read(Block[0], SizeOf(Block[0]));
      FS.Read(Block[1], SizeOf(Block[1]));
    finally
      FS.Free;
    end;
{$ENDIF}
    EncryptLQC(Key, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));
    IV := Block;
  end else begin
    {read the frist block to prime the IV}
    InStream.Read(Block, SizeOf(Block));
    Dec(BlockCount);
    IV := Block;
  end;

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);

    if Encrypt then begin
      EncryptLQCCBC(Key, IV, Block, Encrypt);
      IV := Block;
    end else begin
      Work := Block;
      EncryptLQCCBC(Key, IV, Block, Encrypt);
      IV := Work;
    end;

    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptLQCCBC(Key, IV, Block, Encrypt);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptLQCCBC(Key, IV, Block, Encrypt);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;


{ == LockBox Stream Cipher (LSC) =========================================== }
procedure LSCEncryptFile(const InFile, OutFile : string;
            const Key; KeySize : Integer);
var
  Context   : TLSCContext;
  InStream  : TStream;
  OutStream : TStream;
  BytesRead : LongInt;
  Buf       : array[1..2048] of Byte;
begin
  InitEncryptLSC(Key, KeySize, Context);
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      repeat
        BytesRead := InStream.Read(Buf, SizeOf(Buf));
        if BytesRead > 0 then begin
          EncryptLSC(Context, Buf, BytesRead);
          OutStream.WriteBuffer(Buf, BytesRead);

          if Assigned(LbOnProgress) then                                        {!!.06a}
            if InStream.Position mod LbProgressSize = 0 then                    {!!.06a}
              LbOnProgress (InStream.Position, InStream.Size);                  {!!.06a}
        end;
      until BytesRead < SizeOf(Buf);
    finally
      OutStream.Free;
    end;
  finally
    if Assigned(LbOnProgress) then                                              {!!.06a}
      LbOnProgress (InStream.Position, InStream.Size);                          {!!.06a}
    InStream.Free;
  end;
end;


{ == Random Number Generation (RNG) Ciphers ================================ }
procedure RNG32EncryptFile(const InFile, OutFile : string; Key : LongInt);
var
  Context   : TRNG32Context;
  InStream  : TStream;
  OutStream : TStream;
  BytesRead : LongInt;
  Buf       : array[1..2048] of Byte;
begin
  InitEncryptRNG32(Key, Context);
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      repeat
        BytesRead := InStream.Read(Buf, SizeOf(Buf));
        if BytesRead > 0 then begin
          EncryptRNG32(Context, Buf, BytesRead);
          OutStream.WriteBuffer(Buf, BytesRead);

          if Assigned(LbOnProgress) then                                        {!!.06a}
            if InStream.Position mod LbProgressSize = 0 then                    {!!.06a}
              LbOnProgress (InStream.Position, InStream.Size);                  {!!.06a}
        end;
      until BytesRead < SizeOf(Buf);
    finally
      OutStream.Free;
    end;
  finally
    if Assigned(LbOnProgress) then                                              {!!.06a}
      LbOnProgress (InStream.Position, InStream.Size);                          {!!.06a}
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure RNG64EncryptFile(const InFile, OutFile : string;
            KeyHi, KeyLo : LongInt);
var
  Context   : TRNG64Context;
  InStream  : TStream;
  OutStream : TStream;
  BytesRead : LongInt;
  Buf       : array[1..2048] of Byte;
begin
  InitEncryptRNG64(KeyHi, KeyLo, Context);
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      repeat
        BytesRead := InStream.Read(Buf, SizeOf(Buf));
        if BytesRead > 0 then begin
          EncryptRNG64(Context, Buf, BytesRead);
          OutStream.WriteBuffer(Buf, BytesRead);

          if Assigned(LbOnProgress) then                                        {!!.06a}
            if InStream.Position mod LbProgressSize = 0 then                    {!!.06a}
              LbOnProgress (InStream.Position, InStream.Size);                  {!!.06a}
        end;
      until BytesRead < SizeOf(Buf);
    finally
      OutStream.Free;
    end;
  finally
    if Assigned(LbOnProgress) then                                              {!!.06a}
      LbOnProgress (InStream.Position, InStream.Size);                          {!!.06a}
    InStream.Free;
  end;
end;


{ == Triple DES ============================================================ }
procedure TripleDESEncryptFile(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      TripleDESEncryptStream(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TripleDESEncryptFileCBC(const InFile, OutFile : string;
            const Key : TKey128; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      TripleDESEncryptStreamCBC(InStream, OutStream, Key, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TripleDESEncryptStream(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TDESBlock;
  Context    : TTripleDESContext;
  BlockCount : LongInt;
begin
  InitEncryptTripleDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptTripleDES(Context, Block);
    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptTripleDES(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptTripleDES(Context, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;
{ -------------------------------------------------------------------------- }
procedure TripleDESEncryptStreamCBC(InStream, OutStream : TStream;
            const Key : TKey128; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TDESBlock;
  IV         : TDESBlock;
  Work       : TDESBlock;
  Context    : TTripleDESContext;
  BlockCount : LongInt;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  InitEncryptTripleDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
{$IFDEF MSWINDOWS}
    Block[0] := timeGetTime;
    Block[1] := timeGetTime;
    Block[2] := timeGetTime;
    Block[3] := timeGetTime;
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @Block[0], SizeOf( byte ), SizeOf( Block[0] ), fd );
    fread( @Block[1], SizeOf( byte ), SizeOf( Block[1] ), fd );
    fread( @Block[2], SizeOf( byte ), SizeOf( Block[2] ), fd );
    fread( @Block[3], SizeOf( byte ), SizeOf( Block[3] ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
    FS := TFileStream.Create('/dev/random', fmOpenRead);
    try
      FS.Read(Block[0], SizeOf(Block[0]));
      FS.Read(Block[1], SizeOf(Block[1]));
      FS.Read(Block[2], SizeOf(Block[2]));
      FS.Read(Block[3], SizeOf(Block[3]));
    finally
      FS.Free;
    end;
{$ENDIF}

    EncryptTripleDES(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
    IV := Block;
  end else begin
    {read the frist block to prime the IV}
    InStream.Read(Block, SizeOf(Block));
    Dec(BlockCount);
    IV := Block;
  end;

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);

    if Encrypt then begin
      EncryptTripleDESCBC(Context, IV, Block);
      IV := Block;
    end else begin
      Work := Block;
      EncryptTripleDESCBC(Context, IV, Block);
      IV := Work;
    end;

    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptTripleDESCBC(Context, IV, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptTripleDESCBC(Context, IV, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;


{ == Rijndael ============================================================== }
procedure RDLEncryptFile(const InFile, OutFile : string;
            const Key; KeySize : Longint; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      RDLEncryptStream(InStream, OutStream, Key, KeySize, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure RDLEncryptFileCBC(const InFile, OutFile : string;
            const Key; KeySize : Longint; Encrypt : Boolean);
var
  InStream, OutStream : TStream;
begin
  InStream := TFileStream.Create(InFile, fmOpenRead or fmShareDenyWrite);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate);
    try
      RDLEncryptStreamCBC(InStream, OutStream, Key, KeySize, Encrypt);
    finally
      OutStream.Free;
    end;
  finally
    InStream.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure RDLEncryptStream(InStream, OutStream : TStream;
            const Key; KeySize : Longint; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TRDLBlock;
  Context    : TRDLContext;
  BlockCount : LongInt;
begin
  InitEncryptRDL(Key, KeySize, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptRDL(Context, Block);
    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptRDL(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptRDL(Context, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;
{ -------------------------------------------------------------------------- }
procedure RDLEncryptStreamCBC(InStream, OutStream : TStream;
            const Key; KeySize : Longint; Encrypt : Boolean);
var
  I          : LongInt;
  Block      : TRDLBlock;
  IV         : TRDLBlock;
  Work       : TRDLBlock;
  Context    : TRDLContext;
  BlockCount : LongInt;
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  InitEncryptRDL(Key, KeySize, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
{$IFDEF MSWINDOWS}
    Block[0] := timeGetTime;
    Block[1] := timeGetTime;
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @Block[0], SizeOf( byte ), SizeOf( Block[0] ), fd );
    fread( @Block[1], SizeOf( byte ), SizeOf( Block[1] ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
    FS := TFileStream.Create('/dev/random', fmOpenRead);
    try
      FS.Read(Block[0], SizeOf(Block[0]));
      FS.Read(Block[1], SizeOf(Block[1]));
    finally
      FS.Free;
    end;
{$ENDIF}
    EncryptRDL(Context, Block);
    OutStream.Write(Block, SizeOf(Block));
    IV := Block;
  end else begin
    {read the frist block to prime the IV}
    InStream.Read(Block, SizeOf(Block));
    Dec(BlockCount);
    IV := Block;
  end;

  {when encrypting, make sure we have a block with at least one free}
  {byte at the end. used to store the odd byte count value}
  if Encrypt then
    Inc(BlockCount);

  {process all except the last block}
  for I := 1 to BlockCount - 1 do begin
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);

    if Encrypt then begin
      EncryptRDLCBC(Context, IV, Block);
      IV := Block;
    end else begin
      Work := Block;
      EncryptRDLCBC(Context, IV, Block);
      IV := Work;
    end;

    OutStream.Write(Block, SizeOf(Block));

    if Assigned(LbOnProgress) then                                              {!!.06a}
      if InStream.Position mod LbProgressSize = 0 then                          {!!.06a}
        LbOnProgress (InStream.Position, InStream.Size);                        {!!.06a}
  end;

  if Encrypt then begin
    FillChar(Block, SizeOf(Block), #0);

    {set actual number of bytes to read}
    I := (InStream.Size mod SizeOf(Block));
    if InStream.Read(Block, I) <> I then
      raise ECipherException.Create(SInvalidFileFormat);

    {store number of bytes as last byte in last block}
    PByteArray(@Block)^[SizeOf(Block)-1] := I;

    {encrypt and save full block}
    EncryptRDLCBC(Context, IV, Block);
    OutStream.Write(Block, SizeOf(Block));
  end else begin
    {encrypted file is always a multiple of the block size}
    if InStream.Read(Block, SizeOf(Block)) <> SizeOf(Block) then
      raise ECipherException.Create(SInvalidFileFormat);
    EncryptRDLCBC(Context, IV, Block);

    {get actual number of bytes encoded}
    I := PByteArray(@Block)^[SizeOf(Block)-1];

    {save valid portion of block}
    OutStream.Write(Block, I);
  end;
  if Assigned(LbOnProgress) then                                                {!!.06a}
    LbOnProgress (InStream.Position, InStream.Size);                            {!!.06a}
end;


{ == MD5 =================================================================== }
procedure FileHashMD5(var Digest : TMD5Digest; const AFileName : string);
var
  FS : TFileStream;
begin
  FS := TFileStream.Create(AFileName, fmOpenRead);
  try
    StreamHashMD5(Digest, FS);
  finally
    FS.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure StreamHashMD5(var Digest : TMD5Digest; AStream : TStream);
var
  BufSize : Cardinal;
  Buf : array[0..1023] of Byte;
  Context : TMD5Context;
begin
  InitMD5(Context);
  BufSize := AStream.Read(Buf, SizeOf(Buf));
  while (BufSize > 0) do begin
    UpdateMD5(Context, Buf, BufSize);
    BufSize := AStream.Read(Buf, SizeOf(Buf));
  end;
  FinalizeMD5(Context, Digest);
end;


{ == SHA1 ================================================================== }
procedure FileHashSHA1(var Digest : TSHA1Digest; const AFileName : string);
var
  FS : TFileStream;
begin
  FS := TFileStream.Create(AFileName, fmOpenRead);
  try
    StreamHashSHA1(Digest, FS);
  finally
    FS.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure StreamHashSHA1(var Digest : TSHA1Digest; AStream : TStream);
var
  BufSize : Cardinal;
  Buf : array[0..1023] of Byte;
  Context : TSHA1Context;
begin
  InitSHA1(Context);
  BufSize := AStream.Read(Buf, SizeOf(Buf));
  while (BufSize > 0) do begin
    UpdateSHA1(Context, Buf, BufSize);
    BufSize := AStream.Read(Buf, SizeOf(Buf));
  end;
  FinalizeSHA1(Context, Digest);
end;



begin                                                                           {!!.06a}
  LbOnProgress := nil;                                                          {!!.06a}
  LbProgressSize := 64;                                                         {!!.06a}
end.