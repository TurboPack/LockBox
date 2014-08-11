unit DSASig1;

interface

uses
{$IFDEF WIN32}
  Windows,
  Messages,
  Graphics,
  Controls,
  Forms,
  Dialogs,
  StdCtrls,
  ComCtrls,
{$ENDIF}
{$IFDEF LINUX}
  QForms,
  QStdCtrls,
  QControls,
  QExtCtrls,
  QComCtrls,
{$ENDIF}
  SysUtils,
  Classes,
  LbCipher,
  LbClass,
  LbAsym,
  LbDSA, Menus;

type
  TfrmDSASig = class(TForm)
    LbDSA1: TLbDSA;
    StatusBar1: TStatusBar;
    GroupBox1: TGroupBox;
    Label1: TLabel;
    edtPriQ: TEdit;
    Label2: TLabel;
    mmoPriP: TMemo;
    Label3: TLabel;
    mmoPriG: TMemo;
    Label4: TLabel;
    edtPriX: TEdit;
    GroupBox2: TGroupBox;
    Label5: TLabel;
    Label9: TLabel;
    Label10: TLabel;
    Label11: TLabel;
    edtPubQ: TEdit;
    mmoPubP: TMemo;
    mmoPubG: TMemo;
    GroupBox3: TGroupBox;
    Label7: TLabel;
    Label8: TLabel;
    edtR: TEdit;
    edtS: TEdit;
    GroupBox4: TGroupBox;
    mmoMsg: TMemo;
    mnuMain: TMainMenu;
    mnuFile: TMenuItem;
    mnuDSAKeys: TMenuItem;
    mnuFileOpen: TMenuItem;
    mnuFileClose: TMenuItem;
    mnuDSAKeysGenerate: TMenuItem;
    mnuDSAKeysPub: TMenuItem;
    mnuDSAKeysPri: TMenuItem;
    mnuDSAKeysPubSave: TMenuItem;
    mnuDSAKeysPubLoad: TMenuItem;
    mnuDSAKeysPubClear: TMenuItem;
    mnuDSAKeysPriSave: TMenuItem;
    mnuDSAKeysPriLoad: TMenuItem;
    mnuDSAKeysPriClear: TMenuItem;
    N1: TMenuItem;
    mnuFileExit: TMenuItem;
    mnuFileSign: TMenuItem;
    mnuFileVerify: TMenuItem;
    dlgOpenTxt: TOpenDialog;
    dlgOpenASN: TOpenDialog;
    dlgSaveASN: TSaveDialog;
    mmoPubY: TMemo;
    procedure LbDSA1GetR(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1GetS(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1Progress(Sender: TObject; var Abort: Boolean);
    procedure mnuDSAKeysGenerateClick(Sender: TObject);
    procedure mnuFileSignClick(Sender: TObject);
    procedure mnuFileVerifyClick(Sender: TObject);
    procedure mnuFileOpenClick(Sender: TObject);
    procedure mnuFileCloseClick(Sender: TObject);
    procedure mnuFileExitClick(Sender: TObject);
    procedure mnuDSAKeysPubSaveClick(Sender: TObject);
    procedure mnuDSAKeysPriSaveClick(Sender: TObject);
    procedure mnuDSAKeysPubLoadClick(Sender: TObject);
    procedure mnuDSAKeysPriLoadClick(Sender: TObject);
    procedure mnuDSAKeysPubClearClick(Sender: TObject);
    procedure mnuDSAKeysPriClearClick(Sender: TObject);
  private
    procedure UpdatePrivateKeyFields;
    procedure UpdatePublicKeyFields;
  public
    { Public declarations }
  end;

var
  frmDSASig: TfrmDSASig;

implementation

{$R *.dfm}

uses
  LbUtils, DSASig2;


procedure TfrmDSASig.mnuFileOpenClick(Sender: TObject);
begin
  if dlgOpenTxt.Execute then begin
    mnuFileCloseClick(nil);
    mmoMsg.Lines.LoadFromFile(dlgOpenTxt.FileName);
  end;
end;

procedure TfrmDSASig.UpdatePrivateKeyFields;
begin
  edtPriQ.Text := LbDSA1.PrivateKey.QAsString;
  mmoPriP.Lines.Text := LbDSA1.PrivateKey.PAsString;
  mmoPriG.Lines.Text := LbDSA1.PrivateKey.GAsString;
  edtPriX.Text := LbDSA1.PrivateKey.XAsString;
end;

procedure TfrmDSASig.UpdatePublicKeyFields;
begin
  edtPubQ.Text := LbDSA1.PublicKey.QAsString;
  mmoPubP.Lines.Text := LbDSA1.PublicKey.PAsString;
  mmoPubG.Lines.Text := LbDSA1.PublicKey.GAsString;
  mmoPubY.Lines.Text := LbDSA1.PublicKey.YAsString;
end;

procedure TfrmDSASig.mnuFileSignClick(Sender: TObject);
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := ' Signing message';
  try
    LbDSA1.SignString(mmoMsg.Lines.Text);
    edtR.Text := LbDSA1.SignatureR.IntStr;
    edtS.Text := LbDSA1.SignatureS.IntStr;
    StatusBar1.SimpleText := '';
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TfrmDSASig.mnuFileVerifyClick(Sender: TObject);
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := ' Verifying signature';
  try
    if LbDSA1.VerifyString(mmoMsg.Lines.Text) then
      StatusBar1.SimpleText := ' Verification PASSED'
    else
      StatusBar1.SimpleText := ' Verification FAILED';
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TfrmDSASig.mnuFileCloseClick(Sender: TObject);
begin
  mmoMsg.Clear;
  edtR.Text := '';
  edtS.Text := '';
end;

procedure TfrmDSASig.mnuFileExitClick(Sender: TObject);
begin
  Close;
end;

procedure TfrmDSASig.mnuDSAKeysGenerateClick(Sender: TObject);
begin
  with TdlgKeySize.Create(Application) do begin
    try
      if (ShowModal = mrOk) then begin
        LbDSA1.KeySize := TLbAsymKeySize(cbxKeySize.ItemIndex);
        LbDSA1.PrimeTestIterations := (cbxIterations.ItemIndex + 1) * 5;
      end else
        Exit;
    finally
      Free;
    end;
  end;

  mnuDSAKeysPubClearClick(nil);
  mnuDSAKeysPriClearClick(nil);
  Screen.Cursor := crHourGlass;
  StatusBar1.SimpleText := ' Generating DSA public/private keys - this may take a while';
  try
    LBDSA1.GenerateKeyPair;
    UpdatePrivateKeyFields;
    UpdatePublicKeyFields;
    StatusBar1.SimpleText := '';
    Screen.Cursor := crDefault;
  except
    StatusBar1.SimpleText := ' DSA parameter failure';
    Screen.Cursor := crDefault;
  end;
end;

procedure TfrmDSASig.mnuDSAKeysPubSaveClick(Sender: TObject);
begin
  if dlgSaveASN.Execute then
    LbDSA1.PublicKey.StoreToFile(dlgSaveASN.FileName);
end;

procedure TfrmDSASig.mnuDSAKeysPriSaveClick(Sender: TObject);
begin
  if dlgSaveASN.Execute then
    LbDSA1.PrivateKey.StoreToFile(dlgSaveASN.FileName);
end;

procedure TfrmDSASig.mnuDSAKeysPubLoadClick(Sender: TObject);
begin
  if dlgOpenASN.Execute then begin
    LbDSA1.PublicKey.LoadFromFile(dlgOpenASN.FileName);
    UpdatePublicKeyFields;
  end;
end;

procedure TfrmDSASig.mnuDSAKeysPriLoadClick(Sender: TObject);
begin
  if dlgOpenASN.Execute then begin
    LbDSA1.PrivateKey.LoadFromFile(dlgOpenASN.FileName);
    UpdatePrivateKeyFields;
  end;
end;

procedure TfrmDSASig.mnuDSAKeysPubClearClick(Sender: TObject);
begin
  LbDSA1.PublicKey.Clear;
  UpdatePublicKeyFields;
end;

procedure TfrmDSASig.mnuDSAKeysPriClearClick(Sender: TObject);
begin
  LbDSA1.PrivateKey.Clear;
  UpdatePrivateKeyFields;
end;

procedure TfrmDSASig.LbDSA1GetR(Sender: TObject; var Block: TLbDSABlock);
begin
  HexToBuffer(edtR.Text, Block, SizeOf(Block));
end;

procedure TfrmDSASig.LbDSA1GetS(Sender: TObject; var Block: TLbDSABlock);
begin
  HexToBuffer(edtS.Text, Block, SizeOf(Block));
end;

procedure TfrmDSASig.LbDSA1Progress(Sender: TObject; var Abort: Boolean);
begin
  Application.ProcessMessages;
end;



end.
