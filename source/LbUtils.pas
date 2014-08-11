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
{*                  LBUTILS.PAS 2.08                     *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbUtils;
  {- odds-n-ends }

interface

uses
  SysUtils;

function BufferToHex(const Buf; BufSize : Cardinal) : string;
function HexToBuffer(const Hex : string; var Buf; BufSize : Cardinal) : Boolean;
function Min(A, B : LongInt) : LongInt;
function Max(A, B : LongInt) : LongInt;
function CompareBuffers(const Buf1, Buf2; BufSize : Cardinal) : Boolean;

{$IFDEF Debugging}
procedure DebugStr(const AStr : string);
procedure DebugLogFile(const AFileName : string);
{$ENDIF}

implementation


{$IFDEF Debugging}
var
  DebugLogFileName : string = 'LbDebug.txt';

procedure DebugStr(const AStr : string);
var
  F : TextFile;
begin
  try
    AssignFile(F, DebugLogFileName);
    Append(F);
  except
    on E : EInOutError do
      if (E.ErrorCode = 2) or (E.ErrorCode = 32) then
        Rewrite(F)
      else
        raise;
  end;
  WriteLn(F, AStr);
  Close(F);
  if IOResult <> 0 then ;
end;

procedure DebugLogFile(const AFileName : string);
begin
  if FileExists(AFileName) then
    DeleteFile(AFileName);
  DebugLogFileName := AFileName;
end;
{$ENDIF}


{ -------------------------------------------------------------------------- }
function BufferToHex(const Buf; BufSize : Cardinal) : string;
var
  I     : LongInt;
begin
  Result := '';
  for I := 0 to BufSize - 1 do
    Result := Result + IntToHex(TByteArray(Buf)[I], 2);              {!!.01}
end;
{ -------------------------------------------------------------------------- }
function HexToBuffer(const Hex : string; var Buf; BufSize : Cardinal) : Boolean;
var
  i, C  : Integer;
  Str   : string;
  Count : Integer;
begin
  Result := False;
  Str := '';
  for i := 1 to Length(Hex) do
    if {$IFDEF Unicode}CharInSet(UpCase(Hex[i]), ['0'..'9', 'A'..'F']){$ELSE} Upcase(Hex[i]) in ['0'..'9', 'A'..'F'] {$ENDIF} then
      Str := Str + Hex[i];

  FillChar(Buf, BufSize, #0);
  Count := Min(Length(Hex), BufSize);

  for i := 0 to Count - 1 do begin
    Val('$' + Copy(Str, (i shl 1) + 1, 2), TByteArray(Buf)[i], C);   {!!.01}
    if (C <> 0) then
      Exit;
  end;

  Result := True;
end;
{ -------------------------------------------------------------------------- }
function Min(A, B : LongInt) : LongInt;
begin
  if A < B then
    Result := A
  else
    Result := B;
end;
{ -------------------------------------------------------------------------- }
function Max(A, B : LongInt) : LongInt;
begin
  if A > B then
    Result := A
  else
    Result := B;
end;
{ -------------------------------------------------------------------------- }
function CompareBuffers(const Buf1, Buf2; BufSize : Cardinal) : Boolean;
  { return true if buffers are the same }
var
  i : Integer;
begin
  Result := False;
  for i := 0 to Pred(BufSize) do begin
    Result := TByteArray(Buf1)[i] = TByteArray(Buf2)[i];
    if not Result then
      Break;
  end;
end;

end.

