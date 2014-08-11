unit RSACmp1;

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
  LbRSA,
  LbCipher,
  LbClass,
  LbAsym;

type
  TForm1 = class(TForm)
    btnEncrypt: TButton;
    btnDecrypt: TButton;
    mmoPlainText1: TMemo;
    Label5: TLabel;
    mmoCipherText: TMemo;
    Label7: TLabel;
    mmoPlainText2: TMemo;
    Label6: TLabel;
    btnGenKeys: TButton;
    LbRSA1: TLbRSA;
    StatusBar1: TStatusBar;
    cbxKeySize: TComboBox;
    Label1: TLabel;
    procedure btnEncryptClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure btnGenKeysClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure cbxKeySizeChange(Sender: TObject);
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

uses
  LbUtils;

const
  sEncrypt = ' Encrypting';
  sDecrypt = ' Decrypting';
  sPatience = ' Generating RSA key pair - this may take a while';


procedure TForm1.FormCreate(Sender: TObject);
  { initialize edit controls }
begin
  cbxKeySize.ItemIndex := Ord(LbRSA1.KeySize);
end;

procedure TForm1.btnGenKeysClick(Sender: TObject);
  { generate RSA key pair }
begin
  Screen.Cursor := crHourGlass;
  StatusBar1.SimpleText := sPatience;
  try
    LbRSA1.GenerateKeyPair;
    btnEncrypt.Enabled := True;
    btnDecrypt.Enabled := True;
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnEncryptClick(Sender: TObject);
  { encrypt plaintext string }
begin
  Screen.Cursor := crHourGlass;
  StatusBar1.SimpleText := sEncrypt;
  try
    mmoCipherText.Text := LbRSA1.EncryptString(mmoPlainText1.Text);
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
  mmoPlainText2.Clear;
end;

procedure TForm1.btnDecryptClick(Sender: TObject);
  { decrypt encoded ciphertext }
begin
  Screen.Cursor := crHourGlass;
  StatusBar1.SimpleText := sDecrypt;
  try
    mmoPlainText2.Text := LbRSA1.DecryptString(mmoCipherText.Text);
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.cbxKeySizeChange(Sender: TObject);
  { key size changed }
begin
  LbRSA1.KeySize := TLbAsymKeySize(cbxKeySize.ItemIndex);
end;

end.
