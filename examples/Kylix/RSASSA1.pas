unit RSASSA1;

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
  LbRSA;

type
  TForm1 = class(TForm)
    LbRSASSA1: TLbRSASSA;
    StatusBar1: TStatusBar;
    Label1: TLabel;
    mmoSignature: TMemo;
    GroupBox1: TGroupBox;
    Label2: TLabel;
    cbxKeySize: TComboBox;
    btnGenKeys: TButton;
    Label4: TLabel;
    edtMsg: TEdit;
    btnSign: TButton;
    btnVerify: TButton;
    Label3: TLabel;
    cbxHashMethod: TComboBox;
    chkAbort: TCheckBox;
    procedure btnSignClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnGenKeysClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure cbxKeySizeChange(Sender: TObject);
    procedure cbxHashMethodChange(Sender: TObject);
    procedure LbRSASSA1GetSignature(Sender: TObject;
      var Sig: TRSASignatureBlock);
    procedure LbRSASSA1Progress(Sender: TObject; var Abort: Boolean);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

uses
  LbUtils;

const
  sPass = ' Signature verification: PASSED';
  sFail = ' Signature verification: FAILED';
  sSigning = ' Generating signature';
  sPatience = ' Generating RSA key pair- this may take a while';
  sAbort = ' Key generation aborted';

procedure TForm1.FormCreate(Sender: TObject);
  { initialize edit controls }
begin
  cbxHashMethod.ItemIndex := Ord(LbRSASSA1.HashMethod);
  cbxKeySize.ItemIndex := Ord(LbRSASSA1.KeySize) - 1;
end;

procedure TForm1.btnGenKeysClick(Sender: TObject);
  { generate RSA key pair }
begin
  Screen.Cursor := crAppStart;
  StatusBar1.SimpleText := sPatience;
  try
    LbRSASSA1.GenerateKeyPair;
  finally
    Screen.Cursor := crDefault;
    if chkAbort.Checked then
      StatusBar1.SimpleText := sAbort
    else
      StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnSignClick(Sender: TObject);
  { sign message string, display signature as hex string }
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := sSigning;
  try
    LbRSASSA1.SignString(edtMsg.Text);
    mmoSignature.Text := LbRSASSA1.Signature.IntStr;
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnVerifyClick(Sender: TObject);
  { verify signature against message }
begin
  if LbRSASSA1.VerifyString(edtMsg.Text) then
    StatusBar1.SimpleText := sPass
  else
    StatusBar1.SimpleText := sFail;
end;

procedure TForm1.LbRSASSA1GetSignature(Sender: TObject;
  var Sig: TRSASignatureBlock);
  { convert signature string to binary and return it }
begin
  HexToBuffer(mmoSignature.Text, Sig, SizeOf(Sig));
end;

procedure TForm1.cbxKeySizeChange(Sender: TObject);
  { key size changed }
begin
  LbRSASSA1.KeySize := TLbAsymKeySize(cbxKeySize.ItemIndex + 1);
end;

procedure TForm1.cbxHashMethodChange(Sender: TObject);
  { hash method changed }
begin
  LbRSASSA1.HashMethod := TRSAHashMethod(cbxHashMethod.ItemIndex);
end;

procedure TForm1.LbRSASSA1Progress(Sender: TObject; var Abort: Boolean);
  { process message loop and abort if need be }
begin
  Application.ProcessMessages;
  Abort := chkAbort.Checked;
end;

end.
