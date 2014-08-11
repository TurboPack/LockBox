unit ExFile1;

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
  Buttons,
{$ENDIF}
{$IFDEF LINUX}
  QForms,
  QDialogs,
  QStdCtrls,
  QControls,
  QButtons,
{$ENDIF}
  SysUtils,
  Classes;

type
  TForm1 = class(TForm)
    btnGo: TButton;
    Label4: TLabel;
    cbxCipher: TComboBox;
    edtInFile: TEdit;
    edtOutFile: TEdit;
    SpeedButton1: TSpeedButton;
    SpeedButton2: TSpeedButton;
    Label1: TLabel;
    Label2: TLabel;
    chkEncrypt: TCheckBox;
    OpenDialog1: TOpenDialog;
    SaveDialog1: TSaveDialog;
    Label3: TLabel;
    edtPassphrase: TEdit;
    procedure btnGoClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure SpeedButton1Click(Sender: TObject);
    procedure SpeedButton2Click(Sender: TObject);
  private
    procedure RefreshKeys;
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

uses
  LbCipher, LbProc;

type
  TEncryption = (eBf, eBfCbc, eDes, eDesCbc, e3Des, e3DesCbc, eRdl, eRdlCbc);

var
  Key64            : TKey64;
  Key128           : TKey128;
  Key192           : TKey192;
  Key256           : TKey256;


procedure TForm1.FormCreate(Sender: TObject);
begin
  cbxCipher.ItemIndex := Integer(eDes);
end;

procedure TForm1.btnGoClick(Sender: TObject);
begin
  Screen.Cursor := crHourglass;
  RefreshKeys;
  try
    case TEncryption(cbxCipher.ItemIndex) of
      eBf      : BFEncryptFile(edtInfile.Text, edtOutfile.Text, Key128, chkEncrypt.Checked);
      eBfCbc   : BFEncryptFileCBC(edtInfile.Text, edtOutfile.Text, Key128, chkEncrypt.Checked);
      eDes     : DESEncryptFile(edtInfile.Text, edtOutfile.Text, Key64, chkEncrypt.Checked);
      eDesCbc  : DESEncryptFileCBC(edtInfile.Text, edtOutfile.Text, Key64, chkEncrypt.Checked);
      e3Des    : TripleDESEncryptFile(edtInfile.Text, edtOutfile.Text, Key128, chkEncrypt.Checked);
      e3DesCbc : TripleDESEncryptFileCBC(edtInfile.Text, edtOutfile.Text, Key128, chkEncrypt.Checked);
      eRdl     : RDLEncryptFile(edtInfile.Text, edtOutfile.Text, Key128, 16, chkEncrypt.Checked);
      eRdlCbc  : RDLEncryptFileCBC(edtInfile.Text, edtOutfile.Text, Key128, 16, chkEncrypt.Checked);
    end;
  finally
    Screen.Cursor := crDefault;
  end;
end;

procedure TForm1.SpeedButton1Click(Sender: TObject);
begin
  if OpenDialog1.Execute then
    edtInFile.Text := OpenDialog1.FileName;
end;

procedure TForm1.SpeedButton2Click(Sender: TObject);
begin
  if SaveDialog1.Execute then
    edtOutfile.Text := SaveDialog1.FileName;
end;

procedure TForm1.RefreshKeys;
begin
  GenerateLMDKey(Key64, SizeOf(Key64),   edtPassphrase.Text);
  GenerateLMDKey(Key128, SizeOf(Key128), edtPassphrase.Text);
  GenerateLMDKey(Key192, SizeOf(Key192), edtPassphrase.Text);
  GenerateLMDKey(Key256, SizeOf(Key256), edtPassphrase.Text);
end;

end.
