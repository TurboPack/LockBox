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
{*                  LBUTILS.PAS 2.08                     *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbUtils;
  {- odds-n-ends }

interface

uses
  System.Types, System.SysUtils;

type
  PDWord = ^DWord;

function BufferToHex(const Buf; BufSize : Cardinal) : string;
function HexToBuffer(const Hex : string; var Buf; BufSize : Cardinal) : Boolean;

implementation

uses
  System.Math, System.Character;

{ -------------------------------------------------------------------------- }
function BufferToHex(const Buf; BufSize : Cardinal) : string;
var
  I     : Integer;
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
  cChar: Char;
begin
  Result := False;
  Str := '';
  for cChar in Hex do
  begin
    if cChar.ToUpper.IsInArray(['0','1','2','3','4','5','6','7','8','9', 'A','B','C','D','E','F']) then
      Str := Str + cChar;
  end;

  FillChar(Buf, BufSize, #0);
  Count := Min(Length(Hex), BufSize);

  for i := 0 to Count - 1 do
  begin
    Val('$' + Str.Substring(i shl 1, 2), TByteArray(Buf)[i], C);   {!!.01}
    if C <> 0 then
      Exit;
  end;

  Result := True;
end;

end.


