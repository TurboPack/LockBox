unit HashCmp1;

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
  QDialogs,
  QControls,
  QStdCtrls,
  QExtCtrls,
{$ENDIF}
  SysUtils,
  Classes,
  LbClass,
  LbCipher;

type
  TForm1 = class(TForm)
    LbMD51: TLbMD5;
    LbSHA11: TLbSHA1;
    btnHashFile: TButton;
    edtHash: TEdit;
    OpenDialog1: TOpenDialog;
    rgHashMethod: TRadioGroup;
    btnHashString: TButton;
    procedure btnHashFileClick(Sender: TObject);
    procedure btnHashStringClick(Sender: TObject);
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

var
  MD5Digest : TMD5Digest;
  SHA1Digest : TSHA1Digest;

procedure TForm1.btnHashFileClick(Sender: TObject);
begin
  if OpenDialog1.Execute then begin
    case rgHashMethod.ItemIndex of
      0 : begin
            LbMD51.HashFile(OpenDialog1.FileName);
            LbMD51.GetDigest(MD5Digest);
            edtHash.Text := BufferToHex(MD5Digest, SizeOf(MD5Digest));
          end;
      1 : begin
            LbSHA11.HashFile(OpenDialog1.FileName);
            LbSHA11.GetDigest(SHA1Digest);
            edtHash.Text := BufferToHex(SHA1Digest, SizeOf(SHA1Digest));
          end;
    end;
  end;
end;

procedure TForm1.btnHashStringClick(Sender: TObject);
var
  S : string;
begin
  S := '';
  if InputQuery('HashCmp', 'Enter String', S) then begin
    case rgHashMethod.ItemIndex of
      0 : begin
            LbMD51.HashString(S);
            LbMD51.GetDigest(MD5Digest);
            edtHash.Text := BufferToHex(MD5Digest, SizeOf(MD5Digest));
          end;
      1 : begin
            LbSHA11.HashString(S);
            LbSHA11.GetDigest(SHA1Digest);
            edtHash.Text := BufferToHex(SHA1Digest, SizeOf(SHA1Digest));
          end;
    end;
  end;
end;

end.
