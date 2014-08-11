unit ExRSAKe1;

interface

uses
{$IFDEF WIN32}
  Windows,
  Messages,
  Forms,
  Graphics,
  Controls,
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
  LbRSA;

type
  TForm1 = class(TForm)
    GroupBox4: TGroupBox;
    btnCreateKeys: TButton;
    btnFreeKeys: TButton;
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
    StatusBar1: TStatusBar;
    cbxKeySize: TComboBox;
    Label8: TLabel;
    procedure btnCreateKeysClick(Sender: TObject);
    procedure btnFreeKeysClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnLoadPublicClick(Sender: TObject);
    procedure btnSavePublicClick(Sender: TObject);
    procedure btnLoadPrivateClick(Sender: TObject);
    procedure btnSavePrivateClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    procedure FreeKey(var Key : TLbRSAKey);
    procedure CreateKey(var Key : TLbRSAKey);
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

var
  PublicKey  : TLbRSAKey;
  PrivateKey : TLbRSAKey;


procedure TForm1.FormCreate(Sender: TObject);
begin
  PrivateKey := nil;
  PublicKey  := nil;
  cbxKeySize.ItemIndex := Ord(aks128);
end;

procedure TForm1.CreateKey(var Key : TLbRSAKey);
begin
  FreeKey(Key);
  Key := TLbRSAKey.Create(TLbAsymKeySize(cbxKeySize.ItemIndex));
end;

procedure TForm1.FreeKey(var Key : TLbRSAKey);
begin
  if (Key <> nil) then begin
    Key.Free;
    Key := nil;
  end;
end;

procedure TForm1.btnCreateKeysClick(Sender: TObject);
begin
  Screen.Cursor := crHourglass;
  FreeKey(PublicKey);
  FreeKey(PrivateKey);
  StatusBar1.SimpleText := 'Generating key pair, this may take a while';
  try
    GenerateRSAKeysEx(PrivateKey, PublicKey, TLbAsymKeySize(cbxKeySize.ItemIndex),
      StrToIntDef(edtIterations.Text, 20), nil);
    edtPublicE.Text  := PublicKey.ExponentAsString;
    edtPublicM.Text  := PublicKey.ModulusAsString;
    edtPrivateE.Text := PrivateKey.ExponentAsString;
    edtPrivateM.Text := PrivateKey.ModulusAsString;
  finally
    Screen.Cursor := crDefault;
    StatusBar1.SimpleText := '';
  end;
end;

procedure TForm1.btnFreeKeysClick(Sender: TObject);
begin
  FreeKey(PrivateKey);
  FreeKey(PublicKey);
  edtPublicE.Text  := '';
  edtPublicM.Text  := '';
  edtPrivateE.Text := '';
  edtPrivateM.Text := '';
end;

procedure TForm1.btnLoadPublicClick(Sender: TObject);
var
  FS : TFileStream;
begin
  if OpenDialog1.Execute then begin
    FS := TFileStream.Create(OpenDialog1.FileName, fmOpenRead);
    Screen.Cursor := crHourGlass;
    try
      CreateKey(PublicKey);
      PublicKey.PassPhrase := edtPublicPhrase.Text;
      PublicKey.LoadFromStream(FS);
      edtPublicE.Text := PublicKey.ExponentAsString;
      edtPublicM.Text := PublicKey.ModulusAsString;
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
  if Assigned(PublicKey) then
    if SaveDialog1.Execute then begin
      FS := TFileStream.Create(SaveDialog1.FileName, fmCreate);
      Screen.Cursor := crHourGlass;
      try
        PublicKey.Passphrase := edtPublicPhrase.Text;
        PublicKey.StoreToStream(FS);
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
      CreateKey(PrivateKey);
      PrivateKey.Passphrase := edtPrivatePhrase.Text;
      PrivateKey.LoadFromStream(FS);
      edtPrivateE.Text := PrivateKey.ExponentAsString;
      edtPrivateM.Text := PrivateKey.ModulusAsString;
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
  if Assigned(PrivateKey) then
    if SaveDialog1.Execute then begin
      FS := TFileStream.Create(SaveDialog1.FileName, fmCreate);
      Screen.Cursor := crHourGlass;
      try
        PrivateKey.Passphrase := edtPrivatePhrase.Text;
        PrivateKey.StoreToStream(FS);
      finally
        FS.Free;
        Screen.Cursor := crDefault;
      end;
    end;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  FreeKey(PublicKey);
  FreeKey(PrivateKey);
end;

end.
