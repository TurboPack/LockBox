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
{$UNDEF UsingCLX}

unit LbDesign;

  {-LockBox About Box and component registration}

interface

uses
  Windows,
  Messages,
  Dialogs,
  ShellAPI,
{$IFDEF Version6}
  DesignIntf,
  DesignEditors,
{$ELSE}
  DsgnIntf,
{$ENDIF}
  StdCtrls,
  Graphics,
  ExtCtrls,
  Controls,
  Forms,
  SysUtils,
  Classes;

type
  TLbAboutForm = class(TForm)
      Panel1: TPanel;
      Bevel2: TBevel;
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
      procedure lblWebMouseDown(Sender: TObject; Button: TMouseButton;
        Shift: TShiftState; X, Y: Integer);
      procedure lblWebMouseUp(Sender: TObject; Button: TMouseButton;
        Shift: TShiftState; X, Y: Integer);
      procedure lblUpdateClick(Sender: TObject);
      procedure lblLiveClick(Sender: TObject);
      procedure lblWebMouseMove(Sender: TObject; Shift: TShiftState; X,
        Y: Integer);
      procedure Panel2MouseMove(Sender: TObject; Shift: TShiftState; X,
        Y: Integer);
      procedure FormMouseMove(Sender: TObject; Shift: TShiftState; X,
        Y: Integer);
    private
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

{$R *.dfm}

uses
  LbClass, LbAsym, LbRSA, LbDSA, LbKeyEd1, LbKeyEd2,
  LbConst;



{ == component registration ================================================ }
procedure Register;
begin
  RegisterComponentEditor(TLbSymmetricCipher, TLbSymmetricKeyEditor);
  RegisterComponentEditor(TLbRSA, TLbRSAKeyEditor);
  RegisterComponentEditor(TLbRSASSA, TLbRSAKeyEditor);

  (* RegisterComponentEditor(TLbDSA, TLbDSAKeyEditor); *)

  RegisterPropertyEditor(TypeInfo(string), TLbBaseComponent, 'Version',
                         TLbVersionProperty);

  RegisterComponents('LockBox',
                     [TLbBlowfish,
                      TLbDES,
                      TLb3DES,
                      TLbRijndael,
                      TLbRSA,
                      TLbMD5,
                      TLbSHA1,
                      TLbDSA, 
                      TLbRSASSA]
                      );
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
  Top := (Screen.Height - Height) div 3;
  Left := (Screen.Width - Width) div 2;
  lblVersion.Caption := 'LockBox ' + sLbVersion;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblWebClick(Sender: TObject);
begin
  if ShellExecute(Handle, nil, 'http://sourceforge.net/projects/tplockbox', '', '', SW_SHOWNORMAL) <= 32 then
    ShowMessage(SNoStart);
  lblWeb.Font.Color := clBlue;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblNewsClick(Sender: TObject);
begin
  if ShellExecute(Handle, nil, 'http://sourceforge.net/forum/forum.php?forum_id=241889', '', '', SW_SHOWNORMAL) <= 32 then
    ShowMessage(SNoStart);
  lblNews.Font.Color := clBlue;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblWebMouseDown(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblWebMouseUp(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblUpdateClick(Sender: TObject);
begin
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblLiveClick(Sender: TObject);
begin
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.lblWebMouseMove(Sender: TObject; Shift: TShiftState;
  X, Y: Integer);
begin
  (Sender as TLabel).Font.Color := clRed;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.Panel2MouseMove(Sender: TObject; Shift: TShiftState;
  X, Y: Integer);
begin
  lblNews.Font.Color := clBlue;
end;
{ -------------------------------------------------------------------------- }
procedure TLbAboutForm.FormMouseMove(Sender: TObject; Shift: TShiftState;
  X, Y: Integer);
begin
  lblWeb.Font.Color := clBlue;
  lblNews.Font.Color := clBlue;
end;
{ -------------------------------------------------------------------------- }
end.
