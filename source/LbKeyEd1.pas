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
{*                  LBKEYED1.PAS 2.07                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*                     VCL header                        *}
{*********************************************************}

{$UNDEF UsingClx}
{$I LockBox.inc}

unit LbKeyEd1;
  {-TKey128 generation dialog}

{$R *.dfm}

interface

uses
{$IFDEF MSWINDOWS}
  Windows,
  Controls,
  Forms,
  Dialogs,
  Graphics,
  Buttons,
  ExtCtrls,
  StdCtrls,
  ComCtrls,
  Tabnotbk,
{$ENDIF}

{$IFDEF Version6}
  DesignIntf,
  DesignEditors,
{$ELSE}
  DsgnIntf,
{$ENDIF}

{$IFDEF UsingCLX}
  QForms,
  QGraphics,
  QControls,
  QStdCtrls,
  QExtCtrls,
{$ENDIF}
  SysUtils,
  Classes;


type
  TfrmSymmetricKey = class(TForm)
    btnClose: TButton;
    Label2: TLabel;
    Label3: TLabel;
    edtKey: TEdit;
    Bevel1: TBevel;
    Label9: TLabel;
    cbxKeySize: TComboBox;
    Label1: TLabel;
    cbxKeyType: TComboBox;
    btnGenerate: TButton;
    edtPassphrase: TEdit;
    procedure FormCreate(Sender: TObject);
    procedure btnGenerateClick(Sender: TObject);
    procedure rgKeyTypeChange(Sender: TObject);
    procedure rgKeySizeChange(Sender: TObject);
    procedure edtPassphraseChange(Sender: TObject);
  end;
type
  TLbSymmetricKeyEditor = class(TDefaultEditor)
  public
    procedure ExecuteVerb(Index : Integer);
      override;
    function GetVerb(Index : Integer) : string;
      override;
    function GetVerbCount : Integer;
      override;
  end;

implementation

uses
  LbUtils, LbCipher;

type
  TKeySizeIndex = (ks64, ks128, ks192, ks256);

const
  KeySizes : array[TKeySizeIndex] of Byte = (8, 16, 24, 32);

var
  Key : array[0..32] of Byte;

{ == TLbSymmetricKeyEditor ================================================= }
procedure TLbSymmetricKeyEditor.ExecuteVerb(Index : Integer);
begin
  if (Index <> 0) then
    Exit;

  with TfrmSymmetricKey.Create(Application) do
    try
      ShowModal;
    finally
      Free;
    end;
end;
{ -------------------------------------------------------------------------- }
function TLbSymmetricKeyEditor.GetVerb(Index : Integer) : string;
begin
  case Index of
    0 : Result := 'Generate Symmetric Key';
  else
    Result := '?';
  end;
end;
{ -------------------------------------------------------------------------- }
function TLbSymmetricKeyEditor.GetVerbCount : Integer;
begin
  Result := 1;
end;


{ == TfrmKeys ============================================================== }
procedure TfrmSymmetricKey.FormCreate(Sender: TObject);
begin
  edtKey.Text := '';
  edtPassphrase.Enabled := False;
  edtPassphrase.Color := clBtnFace;
  cbxKeySize.ItemIndex := Ord(ks128);
  cbxKeyType.ItemIndex := 0;
end;
{ -------------------------------------------------------------------------- }
procedure TfrmSymmetricKey.rgKeyTypeChange(Sender: TObject);
begin
  edtKey.Text := '';
  edtPassphrase.Enabled := (cbxKeyType.ItemIndex <> 0);
  if edtPassphrase.Enabled then
    edtPassphrase.Color := clWindow
  else
    edtPassphrase.Color := clBtnFace;
end;
{ -------------------------------------------------------------------------- }
procedure TfrmSymmetricKey.btnGenerateClick(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  try
    case cbxKeyType.ItemIndex of
      0: GenerateRandomKey(Key, SizeOf(Key));
      1: GenerateLMDKey(Key, SizeOf(Key), {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}(AnsiUpperCase(edtPassphrase.Text)));
      2: GenerateLMDKey(Key, SizeOf(Key), {$IFDEF LOCKBOXUNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF}(edtPassphrase.Text));
    end;
    edtKey.Text := BufferToHex(Key, KeySizes[TKeySizeIndex(cbxKeySize.ItemIndex)]);
  finally
    Screen.Cursor := crDefault;
  end;
end;
{ -------------------------------------------------------------------------- }
procedure TfrmSymmetricKey.rgKeySizeChange(Sender: TObject);
begin
  edtKey.Text := '';
end;
{ -------------------------------------------------------------------------- }
procedure TfrmSymmetricKey.edtPassphraseChange(Sender: TObject);
begin
  edtKey.Text := '';
end;

end.







