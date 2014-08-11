unit RSAKeys1;

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
  LbClass;

type
  TForm1 = class(TForm)
    GroupBox4: TGroupBox;
    btnCreateKeys: TButton;
    GroupBox1: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    Label6: TLabel;
    edtPublicE: TEdit;
    edtPublicM: TEdit;
    btnLoadPublic: TButton;
    btnSavePublic: TButton;
    edtPublicPhrase: TEdit;
    GroupBox2: TGroupBox;
    Label3: TLabel;
    Label4: TLabel;
    Label7: TLabel;
    edtPrivateE: TEdit;
    edtPrivateM: TEdit;
    btnLoadPrivate: TButton;
    btnSavePrivate: TButton;
    edtPrivatePhrase: TEdit;
    OpenDialog1: TOpenDialog;
    SaveDialog1: TSaveDialog;
    Label5: TLabel;
    edtIterations: TEdit;
    LbRSA1: TLbRSA;
    btnClear: TButton;
    Label8: TLabel;
    StatusBar1: TStatusBar;
    Label9: TLabel;
    cbxKeySize: TComboBox;
    procedure btnCreateKeysClick(Sender: TObject);
    procedure btnLoadPublicClick(Sender: TObject);
    procedure btnSavePublicClick(Sender: TObject);
    procedure btnLoadPrivateClick(Sender: TObject);
    procedure btnSavePrivateClick(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}


procedure TForm1.btnCreateKeysClick(Sender: TObject);
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := 'Generating key pair, this may take a while';
  try
    LbRSA1.PrimeTestIterations := StrToIntDef(edtIterations.Text, 20);
    LbRSA1.KeySize := TLbAsymKeySize(cbxKeySize.ItemIndex);
    LbRSA1.GenerateKeyPair;
    edtPublicE.Text  := LbRSA1.PublicKey.ExponentAsString;
    edtPublicM.Text  := LbRSA1.PublicKey.ModulusAsString;
    edtPrivateE.Text := LbRSA1.PrivateKey.ExponentAsString;
    edtPrivateM.Text := LbRSA1.PrivateKey.ModulusAsString;
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnLoadPublicClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if OpenDialog1.Execute then begin
    FS := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
    Screen.Cursor := crHourGlass;
    try
      LbRSA1.PublicKey.PassPhrase := edtPublicPhrase.Text;
      LbRSA1.PublicKey.LoadFromStream(FS);
      edtPublicE.Text := LbRSA1.PublicKey.ExponentAsString;
      edtPublicM.Text := LbRSA1.PublicKey.ModulusAsString;
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnSavePublicClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if SaveDialog1.Execute then begin
    FS := TFileStream.Create(SaveDialog1.FileName, fmCreate);
    Screen.Cursor := crHourGlass;
    try
      LbRSA1.PublicKey.Passphrase := edtPublicPhrase.Text;
      LbRSA1.PublicKey.StoreToStream(FS);
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnLoadPrivateClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if OpenDialog1.Execute then begin
    FS := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
    Screen.Cursor := crHourGlass;
    try
      LbRSA1.PrivateKey.Passphrase := edtPrivatePhrase.Text;
      LbRSA1.PrivateKey.LoadFromStream(FS);
      edtPrivateE.Text := LbRSA1.PrivateKey.ExponentAsString;
      edtPrivateM.Text := LbRSA1.PrivateKey.ModulusAsString;
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnSavePrivateClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if SaveDialog1.Execute then begin
    FS := TFileStream.Create(SaveDialog1.FileName, fmCreate);
    Screen.Cursor := crHourGlass;
    try
      LbRSA1.PrivateKey.Passphrase := edtPrivatePhrase.Text;
      LbRSA1.PrivateKey.StoreToStream(FS);
    finally
      FS.Free;
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnClearClick(Sender: TObject);
begin
  LbRSA1.PrivateKey.Clear;
  LbRSA1.PublicKey.Clear;
  edtPrivateE.Text := '';
  edtPrivateM.Text := '';
  edtPublicE.Text := '';
  edtPublicM.Text := '';
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  cbxKeySize.ItemIndex := Ord(LbRSA1.KeySize);
end;

end.
