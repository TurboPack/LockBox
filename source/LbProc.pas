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
 * Roman Kassebaum
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
  System.Classes, System.SysUtils, LbCipher;

type
  ECipherException = class(Exception);

  TProgressProc = TProc<Integer, Integer>;                                      {!!.06a}

  TLbProgress = record
  strict private class var
    FOnProgress: TProgressProc;
    FProgressSize: Integer;
  private
    class procedure Init; static;
  public
    class property ProgressSize: Integer read FProgressSize write FProgressSize;
    class property OnProgress: TProgressProc read FOnProgress write FOnProgress;
  end;

  TBlowfishEncrypt = class(TBlowfish)
  public
    class procedure BFEncryptFile(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean); static;
    class procedure BFEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean); static;
    class procedure BFEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean); static;
    class procedure BFEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean); static;
  end;

  TDESEncrypt = class(TDES)
  public
    class procedure DESEncryptFile(const InFile, OutFile : string; const Key : TKey64; Encrypt : Boolean); static;
    class procedure DESEncryptFileCBC(const InFile, OutFile : string; const Key : TKey64; Encrypt : Boolean); static;
    class procedure DESEncryptStream(InStream, OutStream : TStream; const Key : TKey64; Encrypt : Boolean); static;
    class procedure DESEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey64; Encrypt : Boolean); static;
    class procedure TripleDESEncryptFile(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean); static;
    class procedure TripleDESEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean); static;
    class procedure TripleDESEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean); static;
    class procedure TripleDESEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean); static;
  end;

  TLBCEncrypt = class(TLBC)
  public
    class procedure LBCEncryptFile(const InFile, OutFile : string; const Key : TKey128; Rounds : Integer; Encrypt : Boolean); static;
    class procedure LBCEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Rounds : Integer; Encrypt : Boolean); static;
    class procedure LBCEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Rounds : Integer; Encrypt : Boolean); static;
    class procedure LBCEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Rounds : Integer; Encrypt : Boolean); static;
    class procedure LQCEncryptFile(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean); static;
    class procedure LQCEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean); static;
    class procedure LQCEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean); static;
    class procedure LQCEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean); static;
  end;

  TLSCEncrypt = class(TLSC)
  public
    class procedure LSCEncryptFile(const InFile, OutFile : string; const Key; KeySize : Integer); static;
  end;

  TRNGEncrypt = class(TRNG)
  public
    class procedure RNG32EncryptFile(const InFile, OutFile : string; Key : Integer); static;
    class procedure RNG64EncryptFile(const InFile, OutFile : string; KeyHi, KeyLo : Integer); static;
  end;

  TRDLEncrypt = class(TRDL)
  public
    class procedure RDLEncryptFile(const InFile, OutFile : string; const Key; KeySize : Integer; Encrypt : Boolean); static;
    class procedure RDLEncryptFileCBC(const InFile, OutFile : string; const Key; KeySize : Integer; Encrypt : Boolean); static;
    class procedure RDLEncryptStream(InStream, OutStream : TStream; const Key; KeySize : Integer; Encrypt : Boolean); static;
    class procedure RDLEncryptStreamCBC(InStream, OutStream : TStream; const Key; KeySize : Integer; Encrypt : Boolean); static;
  end;

  TMD5Encrypt = class(TMD5)
  public
    class procedure FileHashMD5(var Digest : TMD5Digest; const AFileName : string); static;
    class procedure StreamHashMD5(var Digest : TMD5Digest; AStream : TStream); static;
  end;

  TSHA1Encrypt = class(TSHA1)
  public
    class procedure FileHashSHA1(var Digest : TSHA1Digest; const AFileName : string); static;
    class procedure StreamHashSHA1(var Digest : TSHA1Digest; AStream : TStream); static;
  end;

implementation

resourcestring
  SInvalidFileFormat = 'Invalid file format';

{ TBlowfishEncrypt }

class procedure TBlowfishEncrypt.BFEncryptFile(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean);
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

class procedure TBlowfishEncrypt.BFEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean);
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

class procedure TBlowfishEncrypt.BFEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TBFBlock;
  Context    : TBFContext;
  BlockCount : Integer;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TBlowfishEncrypt.BFEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean);
var
  I : Integer;
  Block : TBFBlock;
  IV : TBFBlock;
  Work : TBFBlock;
  Context : TBFContext;
  BlockCount : Integer;
begin
  InitEncryptBF(Key, Context);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
    Block[0] := TThread.GetTickCount;
    Block[1] := TThread.GetTickCount;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

{ TDESEncrypt }

class procedure TDESEncrypt.DESEncryptFile(const InFile, OutFile : string; const Key : TKey64; Encrypt : Boolean);
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

class procedure TDESEncrypt.DESEncryptFileCBC(const InFile, OutFile : string; const Key : TKey64; Encrypt : Boolean);
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

class procedure TDESEncrypt.DESEncryptStream(InStream, OutStream : TStream; const Key : TKey64; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TDESBlock;
  Context    : TDESContext;
  BlockCount : Integer;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TDESEncrypt.DESEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey64; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TDESBlock;
  IV         : TDESBlock;
  Work       : TDESBlock;
  Context    : TDESContext;
  BlockCount : Integer;
begin
  InitEncryptDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
    Block[0] := TThread.GetTickCount;
    Block[1] := TThread.GetTickCount;
    Block[2] := TThread.GetTickCount;
    Block[3] := TThread.GetTickCount;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TDESEncrypt.TripleDESEncryptFile(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean);
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

class procedure TDESEncrypt.TripleDESEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean);
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

class procedure TDESEncrypt.TripleDESEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TDESBlock;
  Context    : TTripleDESContext;
  BlockCount : Integer;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TDESEncrypt.TripleDESEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TDESBlock;
  IV         : TDESBlock;
  Work       : TDESBlock;
  Context    : TTripleDESContext;
  BlockCount : Integer;
begin
  InitEncryptTripleDES(Key, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
    Block[1] := TThread.GetTickCount;
    Block[2] := TThread.GetTickCount;
    Block[3] := TThread.GetTickCount;

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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

{ TLBCEncrypt }

class procedure TLBCEncrypt.LBCEncryptFile(const InFile, OutFile : string; const Key : TKey128; Rounds : Integer; Encrypt : Boolean);
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

class procedure TLBCEncrypt.LBCEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Rounds : Integer; Encrypt : Boolean);
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

class procedure TLBCEncrypt.LBCEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Rounds : Integer; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TLBCBlock;
  Context    : TLBCContext;
  BlockCount : Integer;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TLBCEncrypt.LBCEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Rounds : Integer; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TLBCBlock;
  IV         : TLBCBlock;
  Work       : TLBCBlock;
  Context    : TLBCContext;
  BlockCount : Integer;
begin
  InitEncryptLBC(Key, Context, Rounds, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
    Block[0] := TThread.GetTickCount;
    Block[1] := TThread.GetTickCount;
    Block[2] := TThread.GetTickCount;
    Block[3] := TThread.GetTickCount;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TLBCEncrypt.LQCEncryptFile(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean);
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

class procedure TLBCEncrypt.LQCEncryptFileCBC(const InFile, OutFile : string; const Key : TKey128; Encrypt : Boolean);
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

class procedure TLBCEncrypt.LQCEncryptStream(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TLQCBlock;
  BlockCount : Integer;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TLBCEncrypt.LQCEncryptStreamCBC(InStream, OutStream : TStream; const Key : TKey128; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TLQCBlock;
  IV         : TLQCBlock;
  Work       : TLQCBlock;
  BlockCount : Integer;
begin
  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
    Block[0] := TThread.GetTickCount;
    Block[1] := TThread.GetTickCount;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

{ TLSCEncrypt }

class procedure TLSCEncrypt.LSCEncryptFile(const InFile, OutFile : string; const Key; KeySize : Integer);
var
  Context   : TLSCContext;
  InStream  : TStream;
  OutStream : TStream;
  BytesRead : Integer;
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

          if Assigned(TLbProgress.OnProgress) then                                        {!!.06a}
            if InStream.Position mod TLbProgress.ProgressSize = 0 then                    {!!.06a}
              TLbProgress.OnProgress(InStream.Position, InStream.Size);                  {!!.06a}
        end;
      until BytesRead < SizeOf(Buf);
    finally
      OutStream.Free;
    end;
  finally
    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      TLbProgress.OnProgress(InStream.Position, InStream.Size);                          {!!.06a}
    InStream.Free;
  end;
end;

{ TRNGEncrypt }

class procedure TRNGEncrypt.RNG32EncryptFile(const InFile, OutFile : string; Key : Integer);
var
  Context   : TRNG32Context;
  InStream  : TStream;
  OutStream : TStream;
  BytesRead : Integer;
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

          if Assigned(TLbProgress.OnProgress) then                                        {!!.06a}
            if InStream.Position mod TLbProgress.ProgressSize = 0 then                    {!!.06a}
              TLbProgress.OnProgress(InStream.Position, InStream.Size);                  {!!.06a}
        end;
      until BytesRead < SizeOf(Buf);
    finally
      OutStream.Free;
    end;
  finally
    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      TLbProgress.OnProgress(InStream.Position, InStream.Size);                          {!!.06a}
    InStream.Free;
  end;
end;

class procedure TRNGEncrypt.RNG64EncryptFile(const InFile, OutFile : string; KeyHi, KeyLo : Integer);
var
  Context   : TRNG64Context;
  InStream  : TStream;
  OutStream : TStream;
  BytesRead : Integer;
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

          if Assigned(TLbProgress.OnProgress) then                                        {!!.06a}
            if InStream.Position mod TLbProgress.ProgressSize = 0 then                    {!!.06a}
              TLbProgress.OnProgress(InStream.Position, InStream.Size);                  {!!.06a}
        end;
      until BytesRead < SizeOf(Buf);
    finally
      OutStream.Free;
    end;
  finally
    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      TLbProgress.OnProgress(InStream.Position, InStream.Size);                          {!!.06a}
    InStream.Free;
  end;
end;

{ TRDLEncrypt }

class procedure TRDLEncrypt.RDLEncryptFile(const InFile, OutFile : string; const Key; KeySize : Integer; Encrypt : Boolean);
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

class procedure TRDLEncrypt.RDLEncryptFileCBC(const InFile, OutFile : string; const Key; KeySize : Integer; Encrypt : Boolean);
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

class procedure TRDLEncrypt.RDLEncryptStream(InStream, OutStream : TStream; const Key; KeySize : Integer; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TRDLBlock;
  Context    : TRDLContext;
  BlockCount : Integer;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;

class procedure TRDLEncrypt.RDLEncryptStreamCBC(InStream, OutStream : TStream; const Key; KeySize : Integer; Encrypt : Boolean);
var
  I          : Integer;
  Block      : TRDLBlock;
  IV         : TRDLBlock;
  Work       : TRDLBlock;
  Context    : TRDLContext;
  BlockCount : Integer;
begin
  InitEncryptRDL(Key, KeySize, Context, Encrypt);

  {get the number of blocks in the file}
  BlockCount := (InStream.Size div SizeOf(Block));

  if Encrypt then begin
    {set up an initialization vector (IV)}
    Block[0] := TThread.GetTickCount;
    Block[1] := TThread.GetTickCount;
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

    if Assigned(TLbProgress.OnProgress) then                                              {!!.06a}
      if InStream.Position mod TLbProgress.ProgressSize = 0 then                          {!!.06a}
        TLbProgress.OnProgress(InStream.Position, InStream.Size);                        {!!.06a}
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
  if Assigned(TLbProgress.OnProgress) then                                                {!!.06a}
    TLbProgress.OnProgress(InStream.Position, InStream.Size);                            {!!.06a}
end;


{ TMD5Encrypt }

class procedure TMD5Encrypt.FileHashMD5(var Digest : TMD5Digest; const AFileName : string);
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

class procedure TMD5Encrypt.StreamHashMD5(var Digest : TMD5Digest; AStream : TStream);
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

{ TSHA1Encrypt }

class procedure TSHA1Encrypt.FileHashSHA1(var Digest : TSHA1Digest; const AFileName : string);
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

class procedure TSHA1Encrypt.StreamHashSHA1(var Digest : TSHA1Digest; AStream : TStream);
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

{ TLbProgress }

class procedure TLbProgress.Init;
begin
  FProgressSize := 64;                                                         {!!.06a}
end;

initialization
  TLbProgress.Init;

end.
