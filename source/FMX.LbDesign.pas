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
{*                  LBDESIGN.PAS 2.07                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*                       VCL                             *}
{*********************************************************}
{$I LockBox.inc}

unit FMX.LbDesign;

  {-LockBox About Box and component registration}

interface

uses
  System.Classes, FMX.Forms, FMX.StdCtrls, FMX.Objects, FMX.Types, FMX.Controls,
  FMX.Controls.Presentation, DesignIntf, DesignEditors;

type
  TLbAboutForm = class(TForm)
    Panel1: TPanel;
    Bevel2: TPanel;
    Image1: TImage;
    Label1: TLabel;
    lblVersion: TLabel;
    Label3: TLabel;
    lblWeb: TLabel;
    Label9: TLabel;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    Button1: TButton;
    Panel2: TPanel;
    lblNews: TLabel;
    Label2: TLabel;
    procedure Button1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure lblWebClick(Sender: TObject);
    procedure lblNewsClick(Sender: TObject);
    procedure lblWebMouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Single);
    procedure Panel2MouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Single);
    procedure FormMouseMove(Sender: TObject; Shift: TShiftState; X, Y: Single);
  end;

type
  TLbVersionProperty = class(TStringProperty)
  public
    function GetAttributes : TPropertyAttributes; override;
    procedure Edit; override;
  end;


procedure Register;

var
  LbAboutForm: TLbAboutForm;

implementation

{$R *.fmx}

uses
  System.UITypes, Winapi.ShellAPI, Winapi.WIndows, FMX.Platform.Win, FMX.Dialogs,
  LbClass, LbAsym, LbRSA, LbDSA, FMX.LbKeyEd1, FMX.LbKeyEd2, LbConst;



{ == component registration ================================================ }
procedure Register;
begin
  RegisterComponentEditor(TLbSymmetricCipher, TLbSymmetricKeyEditor);
  RegisterComponentEditor(TLbRSA, TLbRSAKeyEditor);
  RegisterComponentEditor(TLbRSASSA, TLbRSAKeyEditor);

  (* RegisterComponentEditor(TLbDSA, TLbDSAKeyEditor); *)

  RegisterPropertyEditor(TypeInfo(string), TLbBaseComponent, 'Version',
                         TLbVersionProperty);
end;


{ == TLbVersionProperty ==================================================== }
function TLbVersionProperty.GetAttributes : TPropertyAttributes;
begin
  Result := [paDialog, paReadOnly];
end;
{ -------------------------------------------------------------------------- }
procedure TLbVersionProperty.Edit;
begin
  with TLbAboutForm.Create(Application) do
    try
      ShowModal;
    finally
      Free;
    end;
end;

{ == TLbAboutForm ========================================================== }
procedure TLbAboutForm.Button1Click(Sender: TObject);
begin
  Close;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.FormCreate(Sender: TObject);
begin
{$IF COMPILERVERSION > 34}
  Top := Trunc(Screen.Height - Height) div 3;
  Left := Trunc(Screen.Width - Width) div 2;
{$ELSE}
  Top := (Screen.Height - Height) div 3;
  Left := (Screen.Width - Width) div 2;
{$IFEND}
  lblVersion.Text := 'LockBox ' + sLbVersion;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblWebClick(Sender: TObject);
begin
  if ShellExecute(WindowHandleToPlatform(Handle).Wnd, nil, 'https://github.com/TurboPack/LockBox', '', '', SW_SHOWNORMAL) <= 32 then
    ShowMessage(SNoStart);
  lblWeb.FontColor := TAlphaColorRec.Blue;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblNewsClick(Sender: TObject);
begin
  if ShellExecute(WindowHandleToPlatform(Handle).Wnd, nil, 'https://github.com/TurboPack/LockBox', '', '', SW_SHOWNORMAL) <= 32 then
    ShowMessage(SNoStart);
  lblNews.FontColor := TAlphaColorRec.Blue;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblWebMouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Single);
begin
  (Sender as TLabel).FontColor := TAlphaColorRec.Red;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.Panel2MouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Single);
begin
  lblNews.FontColor := TAlphaColorRec.Blue;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.FormMouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Single);
begin
  lblWeb.FontColor := TAlphaColorRec.Blue;
  lblNews.FontColor := TAlphaColorRec.Blue;
end;
{ -------------------------------------------------------------------------- }
end.
