unit RDLCmp1;

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
{$ENDIF}
{$IFDEF LINUX}
  QForms,
  QStdCtrls,
  QControls,
{$ENDIF}
  SysUtils,
  Classes,
  LbClass,
  LbCipher;

type
  TForm1 = class(TForm)
    btnEncrypt: TButton;
    btnDecrypt: TButton;
    Label4: TLabel;
    cbxCipherMode: TComboBox;
    mmoPlainText1: TMemo;
    Label5: TLabel;
    mmoCipherText: TMemo;
    Label7: TLabel;
    mmoPlainText2: TMemo;
    Label6: TLabel;
    Label1: TLabel;
    edtPassphrase: TEdit;
    LbRijndael1: TLbRijndael;
    Label2: TLabel;
    cbxKeySize: TComboBox;
    procedure btnEncryptClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure cbxCipherModeChange(Sender: TObject);
    procedure cbxKeySizeChange(Sender: TObject);
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}


procedure TForm1.FormCreate(Sender: TObject);
begin
  cbxCipherMode.ItemIndex := Integer(LbRijndael1.CipherMode);
  cbxKeySize.ItemIndex := Integer(LbRijndael1.KeySize);
end;

procedure TForm1.btnEncryptClick(Sender: TObject);
begin
  LbRijndael1.GenerateKey(edtPassphrase.Text);
  mmoCipherText.Text := LbRijndael1.EncryptString(mmoPlainText1.Text);
  mmoPlainText2.Clear;
end;

procedure TForm1.btnDecryptClick(Sender: TObject);
begin
  LbRijndael1.GenerateKey(edtPassphrase.Text);
  mmoPlainText2.Text := LbRijndael1.DecryptString(mmoCipherText.Text);
end;

procedure TForm1.cbxCipherModeChange(Sender: TObject);
begin
  LbRijndael1.CipherMode := TLbCipherMode(cbxCipherMode.ItemIndex);
end;

procedure TForm1.cbxKeySizeChange(Sender: TObject);
begin
  LbRijndael1.KeySize := TLbKeySizeRDL(cbxKeySize.ItemIndex);
end;

end.
