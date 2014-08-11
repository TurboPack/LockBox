//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "RSACmp1.h"
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
void __fastcall TForm1::btnEncryptClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Encrypting";
  try {
    mmoCipherText->Text = LbRSA1->EncryptString(mmoPlainText1->Text);
  }
  catch (...) {
  } // swallow any errors
  Screen->Cursor = crDefault;
  StatusBar1->SimpleText = "";
  mmoPlainText2->Clear();
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnDecryptClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Decrypting";
  try {
    mmoPlainText2->Text = LbRSA1->DecryptString(mmoCipherText->Text);
  }
  catch (...) {
  } // swallow any errors
  Screen->Cursor = crDefault;
  StatusBar1->SimpleText = "";
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnGenKeysClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Generating RSA key pair- this may take a while";
  try {
    LbRSA1->GenerateKeyPair();
    btnEncrypt->Enabled = True;
    btnDecrypt->Enabled = True;
  }
  catch (...) {
  } // swallow any errors
  Screen->Cursor = crDefault;
  StatusBar1->SimpleText = "";
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  cbxKeySize->ItemIndex = (int) LbRSA1->KeySize;
}
//---------------------------------------------------------------------------

void __fastcall TForm1::cbxKeySizeChange(TObject *Sender)
{
  LbRSA1->KeySize = (TLbAsymKeySize) cbxKeySize->ItemIndex;    
}
//---------------------------------------------------------------------------

