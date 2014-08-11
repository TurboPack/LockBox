//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "RSAKeys1.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbAsym"
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma link "LbRSA"
#pragma resource "*.dfm"
TForm1 *Form1;
//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnCreateKeysClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = "Generating key pair, this may take a while";
  try {
    LbRSA1->PrimeTestIterations = StrToIntDef(edtIterations->Text, 20);
    LbRSA1->KeySize = TLbAsymKeySize(cbxKeySize->ItemIndex);
    LbRSA1->GenerateKeyPair();
    edtPublicE->Text  = LbRSA1->PublicKey->ExponentAsString;
    edtPublicM->Text  = LbRSA1->PublicKey->ModulusAsString;
    edtPrivateE->Text = LbRSA1->PrivateKey->ExponentAsString;
    edtPrivateM->Text = LbRSA1->PrivateKey->ModulusAsString;
  }
  catch (...) {
  } // swallow any errors
  Screen->Cursor = crDefault;
  StatusBar1->SimpleText = "";
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnLoadPublicClick(TObject *Sender)
{
  if (OpenDialog1->Execute()) {
    TFileStream *FS = new TFileStream(OpenDialog1->FileName, fmOpenRead);
    Screen->Cursor = crHourGlass;
    try {
      LbRSA1->PublicKey->Passphrase = edtPublicPhrase->Text;
      LbRSA1->PublicKey->LoadFromStream(FS);
      edtPublicE->Text = LbRSA1->PublicKey->ExponentAsString;
      edtPublicM->Text = LbRSA1->PublicKey->ModulusAsString;
    }
    catch (...) {
    } // swallow any errors
    delete FS;
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSavePublicClick(TObject *Sender)
{
  if (SaveDialog1->Execute()) {
    TFileStream *FS = new TFileStream(SaveDialog1->FileName, fmCreate);
    Screen->Cursor = crHourGlass;
    try {
      LbRSA1->PublicKey->Passphrase = edtPublicPhrase->Text;
      LbRSA1->PublicKey->StoreToStream(FS);
    }
    catch (...) {
    } // swallow any errors
    delete FS;
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnLoadPrivateClick(TObject *Sender)
{
  if (OpenDialog1->Execute()) {
    TFileStream *FS = new TFileStream(OpenDialog1->FileName, fmOpenRead);
    Screen->Cursor = crHourGlass;
    try {
      LbRSA1->PrivateKey->Passphrase = edtPrivatePhrase->Text;
      LbRSA1->PrivateKey->LoadFromStream(FS);
      edtPrivateE->Text = LbRSA1->PrivateKey->ExponentAsString;
      edtPrivateM->Text = LbRSA1->PrivateKey->ModulusAsString;
    }
    catch (...) {
    } // swallow any errors
    delete FS;
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSavePrivateClick(TObject *Sender)
{
  if (SaveDialog1->Execute()) {
    TFileStream *FS = new TFileStream(SaveDialog1->FileName, fmCreate);
    Screen->Cursor = crHourGlass;
    try {
      LbRSA1->PrivateKey->Passphrase = edtPrivatePhrase->Text;
      LbRSA1->PrivateKey->StoreToStream(FS);
    }
    catch (...) {
    } // swallow any errors
    delete FS;
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnClearClick(TObject *Sender)
{
  LbRSA1->PrivateKey->Clear();
  LbRSA1->PublicKey->Clear();
  edtPrivateE->Text = "";
  edtPrivateM->Text = "";
  edtPublicE->Text = "";
  edtPublicM->Text = "";
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  cbxKeySize->ItemIndex = (int) LbRSA1->KeySize;
}
//---------------------------------------------------------------------------

