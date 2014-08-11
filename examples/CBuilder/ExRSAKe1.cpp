//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "ExRSAKe1.h"
#pragma link "LbAsym.obj"
#pragma link "LbRSA.obj"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TForm1 *Form1;

TLbRSAKey *PublicKey;
TLbRSAKey *PrivateKey;

//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  PrivateKey = 0;
  PublicKey  = 0;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FreeKey(TLbRSAKey *Key)
{
  if (Key != 0) {
    delete Key;
    Key = 0;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::CreateKey(TLbRSAKey *Key)
{
  FreeKey(Key);
  Key = new TLbRSAKey((TLbAsymKeySize) cbxKeySize->ItemIndex);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnCreateKeysClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  FreeKey(PublicKey);
  FreeKey(PrivateKey);
  StatusBar1->SimpleText = "Generating key pair, this may take a while";
  try {
    GenerateRSAKeysEx(PrivateKey, PublicKey, TLbAsymKeySize(cbxKeySize->ItemIndex),
      StrToIntDef(edtIterations->Text, 20), 0);
    edtPublicE->Text  = PublicKey->ExponentAsString;
    edtPublicM->Text  = PublicKey->ModulusAsString;
    edtPrivateE->Text = PrivateKey->ExponentAsString;
    edtPrivateM->Text = PrivateKey->ModulusAsString;
  }
  catch (...) {
  }  // swallow any errors
  Screen->Cursor = crDefault;
  StatusBar1->SimpleText = "";
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnFreeKeysClick(TObject *Sender)
{
  FreeKey(PrivateKey);
  FreeKey(PublicKey);
  edtPublicE->Text  = "";
  edtPublicM->Text  = "";
  edtPrivateE->Text = "";
  edtPrivateM->Text = "";
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnLoadPublicClick(TObject *Sender)
{
  if (OpenDialog1->Execute()) {
    TFileStream *FS = new TFileStream(OpenDialog1->FileName, fmOpenRead);
    Screen->Cursor = crHourGlass;
    try {
      CreateKey(PublicKey);
      PublicKey->Passphrase = edtPublicPhrase->Text;
      PublicKey->LoadFromStream(FS);
      edtPublicE->Text = PublicKey->ExponentAsString;
      edtPublicM->Text = PublicKey->ModulusAsString;
    }
    catch (...) {
    }  // swallow any errors
    delete FS;
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSavePublicClick(TObject *Sender)
{
  if (PublicKey !=0) {
    if (SaveDialog1->Execute()) {
      TFileStream *FS = new TFileStream(SaveDialog1->FileName, fmCreate);
      Screen->Cursor = crHourGlass;
      try {
        PublicKey->Passphrase = edtPublicPhrase->Text;
        PublicKey->StoreToStream(FS);
      }
      catch (...) {
      }  // swallow any errors
      delete FS;
      Screen->Cursor = crDefault;
    }
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnLoadPrivateClick(TObject *Sender)
{
  if (OpenDialog1->Execute()) {
    TFileStream *FS = new TFileStream(OpenDialog1->FileName, fmOpenRead);
    Screen->Cursor = crHourGlass;
    try {
      CreateKey(PrivateKey);
      PrivateKey->Passphrase = edtPrivatePhrase->Text;
      PrivateKey->LoadFromStream(FS);
      edtPrivateE->Text = PrivateKey->ExponentAsString;
      edtPrivateM->Text = PrivateKey->ModulusAsString;
    }
    catch (...) {
    }  // swallow any errors
    delete FS;
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSavePrivateClick(TObject *Sender)
{
  if (PrivateKey != 0) {
    if (SaveDialog1->Execute()) {
      TFileStream *FS = new TFileStream(SaveDialog1->FileName, fmCreate);
      Screen->Cursor = crHourGlass;
      try {
        PrivateKey->Passphrase = edtPrivatePhrase->Text;
        PrivateKey->StoreToStream(FS);
      }
      catch (...) {
      }  // swallow any errors
      delete FS;
      Screen->Cursor = crDefault;
    }
  }
}
//---------------------------------------------------------------------------
