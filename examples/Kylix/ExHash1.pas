unit ExHash1;

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
{$ENDIF}
{$IFDEF LINUX}
  QForms,
  QStdCtrls,
  QExtCtrls,
  QControls,
{$ENDIF}
  SysUtils,
  Classes;

type
  TForm1 = class(TForm)
    edtDigest: TEdit;
    Label1: TLabel;
    edtMessage: TEdit;
    Label2: TLabel;
    rgHashMethod: TRadioGroup;
    btnGo: TButton;
    procedure btnGoClick(Sender: TObject);
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
  LbCipher, LbUtils;

type
  THashMethod = (hmMD5, hmSHA1, hmLMD, hmELF);

var
  MD5Digest  : TMD5Digest;
  SHA1Digest : TSHA1Digest;
  ELFDigest  : Longint;
  LMDDigest  : Longint;

procedure TForm1.btnGoClick(Sender: TObject);
begin
  case THashMethod(rgHashMethod.ItemIndex) of
    hmMD5 : begin
              StringHashMD5(MD5Digest, edtMessage.Text);
              edtDigest.Text := BufferToHex(MD5Digest, SizeOf(MD5Digest));
            end;
    hmSHA1 : begin
              StringHashSHA1(SHA1Digest, edtMessage.Text);
              edtDigest.Text := BufferToHex(SHA1Digest, SizeOf(SHA1Digest));
             end;
    hmLMD : begin
              StringHashLMD(LMDDigest, SizeOf(LMDDigest), edtMessage.Text);
              edtDigest.Text := BufferToHex(LMDDigest, SizeOf(LMDDigest));
            end;
    hmELF : begin
              StringHashELF(ELFDigest, edtMessage.Text);
              edtDigest.Text := BufferToHex(ELFDigest, SizeOf(ELFDigest));
            end;
  end;
end;

end.
