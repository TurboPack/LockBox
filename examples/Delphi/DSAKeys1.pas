unit DSAKeys1;

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
  ExtCtrls,
  ComCtrls,
{$ENDIF}
{$IFDEF LINUX}
  QForms,
  QDialogs,
  QControls,
  QExtCtrls,
  QComCtrls,
  QStdCtrls,
{$ENDIF}
  SysUtils,
  Classes,
  LbAsym,
  LbRSA,
  LbCipher,
  LbClass, LbDSA;

type
  TfrmDSAKeys = class(TForm)
    GroupBox4: TGroupBox;
    btnCreateKeys: TButton;
    GroupBox1: TGroupBox;
    Label6: TLabel;
    btnLoadPublic: TButton;
    btnSavePublic: TButton;
    edtPublicPhrase: TEdit;
    GroupBox2: TGroupBox;
    Label7: TLabel;
    btnLoadPrivate: TButton;
    btnSavePrivate: TButton;
    edtPrivatePhrase: TEdit;
    dlgOpenASN: TOpenDialog;
    dlgSaveASN: TSaveDialog;
    Label5: TLabel;
    edtIterations: TEdit;
    btnClear: TButton;
    Label8: TLabel;
    StatusBar1: TStatusBar;
    Label9: TLabel;
    cbxKeySize: TComboBox;
    Label1: TLabel;
    edtPubQ: TEdit;
    Label2: TLabel;
    mmoPubP: TMemo;
    Label10: TLabel;
    mmoPubG: TMemo;
    Label11: TLabel;
    mmoPubY: TMemo;
    Label3: TLabel;
    edtPriQ: TEdit;
    Label4: TLabel;
    mmoPriP: TMemo;
    Label12: TLabel;
    mmoPriG: TMemo;
    Label13: TLabel;
    edtPriX: TEdit;
    LbDSA1: TLbDSA;
    procedure btnCreateKeysClick(Sender: TObject);
    procedure btnLoadPublicClick(Sender: TObject);
    procedure btnSavePublicClick(Sender: TObject);
    procedure btnLoadPrivateClick(Sender: TObject);
    procedure btnSavePrivateClick(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    procedure UpdatePrivateKeyFields;
    procedure UpdatePublicKeyFields;
  end;

var
  frmDSAKeys: TfrmDSAKeys;

implementation

{$R *.dfm}


procedure TfrmDSAKeys.UpdatePrivateKeyFields;
begin
  edtPriQ.Text       := LbDSA1.PrivateKey.QAsString;
  mmoPriP.Lines.Text := LbDSA1.PrivateKey.PAsString;
  mmoPriG.Lines.Text := LbDSA1.PrivateKey.GAsString;
  edtPriX.Text       := LbDSA1.PrivateKey.XAsString;
end;

procedure TfrmDSAKeys.UpdatePublicKeyFields;
begin
  edtPubQ.Text       := LbDSA1.PublicKey.QAsString;
  mmoPubP.Lines.Text := LbDSA1.PublicKey.PAsString;
  mmoPubG.Lines.Text := LbDSA1.PublicKey.GAsString;
  mmoPubY.Lines.Text := LbDSA1.PublicKey.YAsString;
end;

procedure TfrmDSAKeys.btnCreateKeysClick(Sender: TObject);
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := 'Generating key pair, this may take a while';
  try
    LbDSA1.PrimeTestIterations := StrToIntDef(edtIterations.Text, 20);
    LbDSA1.KeySize := TLbAsymKeySize(cbxKeySize.ItemIndex);
    LbDSA1.GenerateKeyPair;
    UpdatePrivateKeyFields;
    UpdatePublicKeyFields;
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TfrmDSAKeys.btnLoadPublicClick(Sender: TObject);
begin
  if dlgOpenASN.Execute then begin
    LbDSA1.PublicKey.Passphrase := edtPublicPhrase.Text;
    LbDSA1.PublicKey.LoadFromFile(dlgOpenASN.FileName);
    UpdatePublicKeyFields;
  end;
end;

procedure TfrmDSAKeys.btnSavePublicClick(Sender: TObject);
begin
  if dlgSaveASN.Execute then begin
    LbDSA1.PublicKey.Passphrase := edtPublicPhrase.Text;
    LbDSA1.PublicKey.StoreToFile(dlgSaveASN.FileName);
  end;
end;

procedure TfrmDSAKeys.btnLoadPrivateClick(Sender: TObject);
begin
  if dlgOpenASN.Execute then begin
    LbDSA1.PrivateKey.Passphrase := edtPrivatePhrase.Text;
    LbDSA1.PrivateKey.LoadFromFile(dlgOpenASN.FileName);
    UpdatePrivateKeyFields;
  end;
end;

procedure TfrmDSAKeys.btnSavePrivateClick(Sender: TObject);
begin
  if dlgSaveASN.Execute then begin
    LbDSA1.PrivateKey.Passphrase := edtPrivatePhrase.Text;
    LbDSA1.PrivateKey.StoreToFile(dlgSaveASN.FileName);
  end;
end;

procedure TfrmDSAKeys.btnClearClick(Sender: TObject);
begin
  LbDSA1.PublicKey.Clear;
  LbDSA1.PrivateKey.Clear;
  UpdatePublicKeyFields;
  UpdatePrivateKeyFields;
end;

procedure TfrmDSAKeys.FormCreate(Sender: TObject);
begin
  cbxKeySize.ItemIndex := Ord(LbDSA1.KeySize);
end;

end.
