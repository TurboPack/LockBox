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
{*                  LBRANDOM.PAS 2.08                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}
{$IFDEF MSWINDOWS}
  {$WRITEABLECONST ON}
{$ENDIF}

unit LbRandom;

interface
uses
{$IFDEF MSWINDOWS}
  Windows, { only needed for get tick count }
{$ENDIF}
{$IFDEF POSIX}
  Types, Classes,
{$ENDIF}
{$IFDEF UsingCLX}
  Types,
{$ENDIF}
{$IFDEF LINUX}
  Libc,
{$ENDIF}
  Sysutils,
  Math,
  LbCipher;

const
  tmp = 1;


{ TLbRandomGenerator }
type
  TLbRandomGenerator = class
    private
      RandCount : Integer;
      Seed : TMD5Digest;
      procedure ChurnSeed;
    public
      constructor Create;
      destructor Destroy; override;
      procedure RandomBytes( var buff; len : DWORD );
  end;


{ TLbRanLFS }
type
  TLbRanLFS = class
    private
      ShiftRegister : DWORD;
      procedure SetSeed;
      function LFS : byte;
    public
      constructor Create;
      destructor Destroy; override;
      procedure FillBuf( var buff; len : DWORD );
  end;


implementation


{ == TLbRandomGenerator ==================================================== }
constructor TLbRandomGenerator.create;
begin
  inherited;
  ChurnSeed;
end;
{ -------------------------------------------------------------------------- }
destructor TLbRandomGenerator.Destroy;
begin
  RandCount := 0;
  FillChar( Seed, SizeOf( Seed ), $00 );
  inherited;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRandomGenerator.ChurnSeed;
var
  RandomSeed : array[ 0..15 ] of byte;
  Context : TMD5Context;
  lcg : TLbRanLFS; 
  i : integer;
begin
  lcg := TLbRanLFS.Create;
  try
    lcg.FillBuf( RandomSeed, SizeOf( RandomSeed ));
    for i := 0 to 4 do begin
      InitMD5( Context );
      UpdateMD5( Context, Seed, SizeOf( Seed ));
      UpdateMD5( Context, RandomSeed, SizeOf( RandomSeed ));
      FinalizeMD5( Context, Seed );
    end;
  finally
    lcg.Free;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRandomGenerator.RandomBytes( var buff; len : DWORD );
var
  Context : TMD5Context;
  TmpDig : TMD5Digest;
  Index : DWORD;
  m : integer;
  SizeOfTmpDig : integer;
begin
  SizeOfTmpDig := SizeOf( TmpDig );
  Index := 0;

  if(( len - Index ) < 16 )then
    m := len - Index
  else
    m := SizeOfTmpDig;

  While Index < len do begin
    InitMD5( Context );
    UpdateMD5( Context, Seed, sizeof( Seed ));
    UpdateMD5( Context, RandCount, sizeof( RandCount ));
    FinalizeMD5( Context, TmpDig );

    inc( RandCount );
    move( tmpDig, TByteArray( buff )[ Index ], m );
    inc( Index, m );

    if(( len - Index ) < 16 )then
      m := len - Index
    else
      m := SizeOfTmpDig;
  end;
end;
{ == TLbRanLFS ============================================================= }
constructor TLbRanLFS.Create;
begin
  inherited;
  SetSeed;
end;
{ -------------------------------------------------------------------------- }
destructor TLbRanLFS.Destroy;
begin
  inherited;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRanLFS.FillBuf( var buff; len : DWORD );
var
  l : DWORD;
  b : byte;
  tmp_byt : byte;
begin
  for l := 0 to pred( len )do begin
    tmp_byt := 0;
    for b := 0 to 7 do begin
      tmp_byt := ( tmp_byt shl 1 ) or LFS;
    end;
    TByteArray( buff )[ l ] := tmp_byt;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TLbRanLFS.SetSeed;
const
  hold : integer = 1;
var
{$IFDEF MSWINDOWS}
  _time : TSYSTEMTIME;
{$ENDIF}
{$IFDEF LINUX}
  fd : pIOFile;
{$ENDIF}
{$IFDEF POSIX}
  FS: TFileStream;
{$ENDIF}
begin
  while true do begin
{$IFDEF MSWINDOWS}
    ShiftRegister := hold;
    GetLocalTime( _time );
    ShiftRegister := ( ShiftRegister shl ( hold and $0000000F )) xor
                     (( DWORD( _time.wHour or _time.wSecond ) shl 16 ) or
                      ( DWORD( _time.wMinute or _time.wMilliseconds  )));
    hold := ShiftRegister;
    inc( hold );
{$ENDIF}
{$IFDEF LINUX}
    fd := fopen( '/dev/random', 'r' );
    fread( @ShiftRegister, SizeOf( byte ), SizeOf( ShiftRegister ), fd );
    fclose( fd );
{$ENDIF}
{$IFDEF POSIX}
  FS := TFileStream.Create('/dev/random', fmOpenRead);
  try
    FS.Read(ShiftRegister, SizeOf(ShiftRegister));
  finally
    FS.Free;
  end;
{$ENDIF}
    if( ShiftRegister <> 0 )then
      break;
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbRanLFS.LFS : byte;
begin
  ShiftRegister := (((( ShiftRegister shr 31 ) xor
                      ( ShiftRegister shr 6  ) xor
                      ( ShiftRegister shr 4  ) xor
                      ( ShiftRegister shr 2  ) xor
                      ( ShiftRegister shr 1  ) xor
                      ( ShiftRegister )) and $00000001 ) shl 31 ) or
                      ( ShiftRegister shr 1 );
                   
  result := ShiftRegister and $00000001;
end;

end.
