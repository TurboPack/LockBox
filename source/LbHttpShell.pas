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
{*                  LbHttpShell.pas 2.01                 *}
{*     Copyright (c) 2001 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}
unit LbHttpShell;

interface

uses
  SysUtils,
  Libc,
  QControls,
  QForms,
  Classes;
type
  EExecError = class(Exception);

type
  THttpShell = class
  private
    procedure GetCurrentPath(PathList : TList);
    function IsBrowserPresent(PathList : TList; Browser : string) : Boolean;
    procedure CallBrowser(Browser : string; Parameters : string;
                          Website : string; XTerm : Boolean);
    function AboutExecAndWait(FileName : PChar; CommandLine : PChar;
                              Wait : Boolean) : Integer;
    procedure FreePaths(PathList : TList);
  public
    procedure StartBrowser(Website : string);
  end;

implementation

type
  TBrowserStartCmd = record
    Command    : string[64];
    Parameters : string [255];
    XTerm      : Boolean; { Start browser in an XTerm }
  end;

const
  cMaxBrowsers = 25;
  cMaxNewsreaders = 18;
  { exception consts }
  cForkFailure = 'Unable to fork process.';
  cExeFailure = 'Unable to execute process.';
  cBrowserFailure = 'Uable to start web browser.' +
                    'Make sure you have it properly set-up on your system.';
  cArgFailure = 'Too many arguments.';

const
  {  A reasonably comprehensive list of browsers to try.  I haven't tested }
  { most of the lesser known ones. }
  cBrowserList : array [1..cMaxBrowsers] of TBrowserStartCmd =
    ((Command : 'mozilla';            Parameters : '<site>'; Xterm : False),
     (Command : 'netscape';           Parameters : '<site>'; Xterm : False),
     (Command : 'konquerer';          Parameters : '<site>'; Xterm : False),
     (Command : 'gnome-help-browser'; Parameters : '<site>'; Xterm : False),
     (Command : 'mosaic';             Parameters : '<site>'; Xterm : False),
     (Command : 'mmosaic';            Parameters : '<site>'; Xterm : False),
     (Command : 'opera';              Parameters : '<site>'; Xterm : False),
     (Command : 'arena';              Parameters : '<site>'; Xterm : False),
     (Command : 'amaya';              Parameters : '<site>'; Xterm : False),
     (Command : 'lynx';               Parameters : '<site>'; Xterm : True),
     (Command : 'kdehelp';            Parameters : '<site>'; Xterm : False), // Requires kfm running
     (Command : 'qtmozilla';          Parameters : '<site>'; Xterm : False),
     (Command : 'cineast';            Parameters : '<site>'; Xterm : False),
     (Command : 'qweb';               Parameters : '<site>'; Xterm : False),
     (Command : 'plume';              Parameters : '<site>'; Xterm : False),
     (Command : 'surfit';             Parameters : '<site>'; Xterm : False), // Now known as plume
     (Command : 'armadillo';          Parameters : '<site>'; Xterm : False),
     (Command : 'w3m';                Parameters : '<site>'; Xterm : True),
     (Command : 'grail';              Parameters : '<site>'; Xterm : False),
     (Command : 'mmm';                Parameters : '<site>'; Xterm : False),
     (Command : 'mneumonic';          Parameters : '<site>'; Xterm : False),
     (Command : 'gzilla';             Parameters : '<site>'; Xterm : False), // Now known as Armadillo
     (Command : 'chimera';            Parameters : '<site>'; Xterm : False), // Chimera 2
     (Command : 'express';            Parameters : '<site>'; Xterm : False), // Verge Express
     (Command : 'jozilla';            Parameters : '<site>'; Xterm : False)); // JoZilla

  NewsreaderList : array [1..cMaxNewsreaders] of TBrowserStartCmd =
    ((Command : 'mozilla';  Parameters : '-news <site>'; XTerm : False),
     (Command : 'netscape'; Parameters : '-news <site>'; XTerm : False),
     (Command : 'pan';      Parameters : '<site>';       XTerm : False),
     (Command : 'kexpress'; Parameters : '<site>';       XTerm : False),
     (Command : 'gnews';    Parameters : '<site>';       XTerm : False),
     (Command : 'knews';    Parameters : '<site>';       XTerm : False),
     (Command : 'gnus';     Parameters : '<site>';       XTerm : False),
     (Command : 'knode';    Parameters : '<site>';       XTerm : False),
     (Command : 'krn';      Parameters : '<site>';       XTerm : False),
     (Command : 'grin';     Parameters : '<site>';       XTerm : False),
     (Command : 'newsflex'; Parameters : '<site>';       XTerm : False),
     (Command : 'xvnews';   Parameters : '<site>';       XTerm : False),
     (Command : 'xrn';      Parameters : '<site>';       XTerm : False),
     (Command : 'tin';      Parameters : '<site>';       Xterm : True),
     (Command : 'slrn';     Parameters : '<site>';       XTerm : True),
     (Command : 'inn';      Parameters : '<site>';       Xterm : True),
     (Command : 'trn';      Parameters : '<site>';       XTerm : True),
     (Command : 'rn';       Parameters : '<site>';       XTerm : True));

{ -------------------------------------------------------------------------- }
procedure THttpShell.FreePaths(PathList : TList);
var
  i : Integer;
begin
  for i := 0 to PathList.Count - 1 do begin
    if Assigned(PathList[i]) then
      StrDispose(PathList[i]);
  end;
end;
{ -------------------------------------------------------------------------- }
function THttpShell.AboutExecAndWait(FileName : PChar; CommandLine : PChar;
                                     Wait : Boolean) : Integer;
const
  MaxArgs = 256;                { Maximum number of arguments that can }
                                { be passed on the command line.       }

var
  Arguments : Array [0..MaxArgs - 1] of PChar;  // Array of arguments

  function GetNextArgument(var StartPos : Cardinal) : PChar;

  // This gets the next argument from the CommandLine.  This function does
  // not take into account arguments that contain quotes.

  var
    FirstPos : Cardinal;
  begin
    if not Assigned(CommandLine) then begin
      Result := nil;
      exit;
    end;

    while(CommandLine[StartPos] = ' ') and (StartPos <= StrLen(CommandLine)) do
      Inc(StartPos);
    FirstPos := StartPos;
    while(CommandLine[StartPos] <> ' ') and (StartPos <= StrLen(CommandLine)) do
      Inc(StartPos);
    if Trim(Copy(CommandLine, FirstPos, StartPos - FirstPos)) = '' then begin
      Result := nil;
      exit;
    end;
    Result := StrAlloc(StartPos - FirstPos + 1);
    StrLCopy(Result, CommandLine + FirstPos, StartPos - FirstPos);
    Result[StartPos - FirstPos + 1] := #$00;
  end;

  function GetFirstArgument : PChar;

  // The first argument should always be the name of the calling program.

  begin
    Result := StrAlloc(StrLen(FileName) + 1);
    StrPLCopy(Result, FileName, StrLen(FileName));
    Result [StrLen(FileName)] := #$00;
  end;

  procedure SplitArguments;
  var
    CurrentArgument : integer;
    StringPosition : Cardinal;
  begin
    StringPosition := 0;
    CurrentArgument := 1;

    Arguments[0] := GetFirstArgument;

    repeat
      Arguments [CurrentArgument] := GetNextArgument(StringPosition);
      Inc(CurrentArgument);
      if CurrentArgument > MaxArgs then
        raise EExecError.Create(cArgFailure);
    until Arguments[CurrentArgument-1] = nil;
  end;

  procedure ReleaseArgumentMemory;
  var
    i : integer;
  begin
    i := 0;
    while(Arguments[i] <> nil) do begin
      StrDispose(Arguments[i]);
      Inc(i);
    end;
  end;

  procedure ForkCommand;
  var
    pid : pid_t;
    Status : integer;
  begin
    pid := fork;
    if pid = -1 then
      raise EExecError.Create(cForkFailure)
    else if pid = 0 then begin
      if execvp(FileName, @Arguments)  = -1 then
        raise EExecError.Create(cExeFailure);
    end else begin
      if Wait then
        waitpid(pid, @status, WUNTRACED);
    end;
  end;

begin
  Result := 0;
  Arguments[0] := nil;
  SplitArguments;
  try
    ForkCommand;
  finally
    ReleaseArgumentMemory;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure THttpShell.CallBrowser(Browser : string; Parameters : string;
                                 Website : string; XTerm : Boolean);
begin
  if Pos('<site>', Parameters) > 0 then begin
    Parameters := Copy(Parameters, 1, Pos('<site>', Parameters) - 1) +
                        Website +
                        Copy(Parameters, Pos('<site>', Parameters) + 6, 255);
  end else
    Parameters := Parameters + ' ' + Website;
  if XTerm then begin
    Parameters := '-e ' + Browser + ' ' + Parameters;
    Browser := 'xterm';
  end;
  AboutExecAndWait(PChar(Browser), PChar(Parameters), False);
end;
{ -------------------------------------------------------------------------- }
function THttpShell.IsBrowserPresent(PathList : TList;
                                        Browser : string) : Boolean;
var
  i : integer;
begin
  Result := False;
  for i := 0 to PathList.Count - 1 do begin
    if FileExists(PChar(PathList[i]) + '/' + Browser) then begin
      Result := True;
      exit;
    end;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure THttpShell.GetCurrentPath(PathList : TList);

  function GetNextPath(Path : PChar; var StartPos : Cardinal) : PChar;
  var
    FirstPos : Cardinal;
  begin
    if not Assigned(Path) then begin
      result := nil;
      exit;
    end;

    while(Path[StartPos] = ':') and(StartPos <= StrLen(Path)) do
      Inc(StartPos);
    FirstPos := StartPos;
    while(Path[StartPos] <> ':') and(StartPos <= StrLen(Path)) do
      Inc(StartPos);
    if Trim(Copy(Path, FirstPos, StartPos - FirstPos)) = '' then begin
      Result := nil;
      exit;
    end;
    Result := StrAlloc(StartPos - FirstPos + 1);
    StrLCopy(Result, Path + FirstPos, StartPos - FirstPos);
    Result[StartPos - FirstPos + 1] := #$00;
  end;

var
  WorkPath : PChar;
  StartPos : Cardinal;
  CurrentPath : PChar;
begin
  WorkPath := getenv('PATH');
  StartPos := 0;
  PathList.Clear;
  repeat
    CurrentPath := GetNextPath(WorkPath, StartPos);
    if Assigned(CurrentPath) then
      PathList.Add(CurrentPath);
  until CurrentPath = nil;
end;
{ -------------------------------------------------------------------------- }
procedure THttpShell.StartBrowser(Website : string);

var
  PathList : TList;
  i : integer;
  SaveCursor:TCursor;
begin
  SaveCursor := Screen.Cursor;
  try
    Screen.Cursor := crHourGlass;
    PathList := TList.Create;
    try
      GetCurrentPath(PathList);
      try
        for i := 1 to cMaxBrowsers do begin
          if IsBrowserPresent(PathList, cBrowserList[i].Command) then begin
            CallBrowser(cBrowserList[i].Command, cBrowserList[i].Parameters,
                        Website, cBrowserList[i].XTerm);
            exit;
          end;
        end;
        raise EExecError.Create(cBrowserFailure);
      finally
        FreePaths(PathList);
      end;
    finally
      PathList.Free;
    end;
  finally
    Screen.Cursor := SaveCursor;
  end;
end;
end.

