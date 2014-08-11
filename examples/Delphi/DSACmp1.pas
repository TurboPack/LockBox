unit DSACmp1;

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
  LbDSA;

type
  TForm1 = class(TForm)
    LbDSA1: TLbDSA;
    btnGenParams: TButton;
    mmoP: TMemo;
    Label1: TLabel;
    Label2: TLabel;
    mmoG: TMemo;
    Label3: TLabel;
    Label4: TLabel;
    mmoY: TMemo;
    Label5: TLabel;
    edtMsg: TEdit;
    Label6: TLabel;
    edtR: TEdit;
    edtS: TEdit;
    btnSign: TButton;
    Label7: TLabel;
    Label8: TLabel;
    edtQ: TEdit;
    edtX: TEdit;
    btnVerify: TButton;
    StatusBar1: TStatusBar;
    edtSeed: TEdit;
    Label9: TLabel;
    Label10: TLabel;
    edtXKey: TEdit;
    Label11: TLabel;
    edtKKey: TEdit;
    btnGenXY: TButton;
    btnSetParams: TButton;
    btnSetXY: TButton;
    chkAbort: TCheckBox;
    procedure btnGenParamsClick(Sender: TObject);
    procedure btnSignClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure btnGenXYClick(Sender: TObject);
    procedure btnSetParamsClick(Sender: TObject);
    procedure btnSetXYClick(Sender: TObject);
    procedure LbDSA1GetSeed(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1GetXKey(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1GetKKey(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1GetR(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1GetS(Sender: TObject; var Block: TLbDSABlock);
    procedure LbDSA1Progress(Sender: TObject; var Abort: Boolean);
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
  LbUtils, LbRSA;


procedure TForm1.btnGenParamsClick(Sender: TObject);
  { generate DSA parameters p, q, and g }
begin
  Screen.Cursor := crHourGlass;
  StatusBar1.SimpleText := ' Generating DSA parameters - this may take a while';

  try
    if LBDSA1.GeneratePQG then begin
      edtQ.Text := LbDSA1.PrivateKey.QAsString;
      mmoP.Lines.Text := LbDSA1.PrivateKey.PAsString;
      mmoG.Lines.Text := LbDSA1.PrivateKey.GAsString;
      StatusBar1.SimpleText := '';
    end else
      StatusBar1.SimpleText := ' DSA parameter failure';
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TForm1.btnGenXYClick(Sender: TObject);
  { generate key parameters x and y }
begin
  Screen.Cursor := crHourGlass;
  StatusBar1.SimpleText := ' Generating X and Y';

  try
    LbDSA1.GenerateXY;
    edtX.Text := LbDSA1.PrivateKey.XAsString;
    mmoY.Lines.Text := LbDSA1.PublicKey.YAsString;
    StatusBar1.SimpleText := '';
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TForm1.btnSignClick(Sender: TObject);
  { sign message }
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := ' Signing message';

  try
    LbDSA1.SignString(edtMsg.Text);
    edtR.Text := LbDSA1.SignatureR.IntStr;
    edtS.Text := LbDSA1.SignatureS.IntStr;
    StatusBar1.SimpleText := '';
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TForm1.btnVerifyClick(Sender: TObject);
  { verify signature }
begin
  Screen.Cursor := crHourglass;
  StatusBar1.SimpleText := ' Verifying signature';

  try
    if LbDSA1.VerifyString(edtMsg.Text) then
      StatusBar1.SimpleText := ' Verification PASSED'
    else
      StatusBar1.SimpleText := ' Verification FAILED';
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TForm1.btnSetParamsClick(Sender: TObject);
  { assign DSA parameters p, q, and g }
begin
  LbDSA1.PrivateKey.QAsString := edtQ.Text;
  LbDSA1.PrivateKey.PAsString := mmoP.Lines.Text;
  LbDSA1.PrivateKey.GAsString := mmoG.Lines.Text;
  LbDSA1.PublicKey.QAsString := edtQ.Text;
  LbDSA1.PublicKey.PAsString := mmoP.Lines.Text;
  LbDSA1.PublicKey.GAsString := mmoG.Lines.Text;
end;

procedure TForm1.btnSetXYClick(Sender: TObject);
  { assign key parameters x and y }
begin
  LbDSA1.PrivateKey.XAsString := edtX.Text;
  LbDSA1.PublicKey.YAsString := mmoY.Text;
end;

procedure TForm1.LbDSA1GetSeed(Sender: TObject; var Block: TLbDSABlock);
  { return seed }
begin
  HexToBuffer(edtSeed.Text, Block, SizeOf(Block));
end;

procedure TForm1.LbDSA1GetXKey(Sender: TObject; var Block: TLbDSABlock);
  { return XKey }
begin
  HexToBuffer(edtXKey.Text, Block, SizeOf(Block));
end;

procedure TForm1.LbDSA1GetKKey(Sender: TObject; var Block: TLbDSABlock);
  { return YKey }
begin
  HexToBuffer(edtKKey.Text, Block, SizeOf(Block));
end;

procedure TForm1.LbDSA1GetR(Sender: TObject; var Block: TLbDSABlock);
  { return signature (r) }
begin
  HexToBuffer(edtR.Text, Block, SizeOf(Block));
end;

procedure TForm1.LbDSA1GetS(Sender: TObject; var Block: TLbDSABlock);
  { return signature (s) }
begin
  HexToBuffer(edtS.Text, Block, SizeOf(Block));
end;

procedure TForm1.LbDSA1Progress(Sender: TObject; var Abort: Boolean);
  { allow message loop to run }
begin
  Application.ProcessMessages;
  Abort := chkAbort.Checked;
end;

end.
