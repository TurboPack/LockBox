//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "ExStrin1.h"
#pragma link "LbCipher.obj"
#pragma link "LbString.obj"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TForm1 *Form1;

TKey64  Key64;
TKey128 Key128;
TKey192 Key192;
TKey256 Key256;
AnsiString PlainText;
AnsiString CipherText;

enum TEncryption { eBf, eBfCbc, eDes, eDesCbc, e3Des, e3DesCbc,
        eLbc, eLbcCbc, eRdl, eRdlCbc };

//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  cbxCipher->ItemIndex = (int) eDes;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnEncryptClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  GenerateLMDKey(Key64, sizeof(Key64),   edtPassphrase->Text);
  GenerateLMDKey(Key128, sizeof(Key128), edtPassphrase->Text);
  GenerateLMDKey(Key192, sizeof(Key192), edtPassphrase->Text);
  GenerateLMDKey(Key256, sizeof(Key256), edtPassphrase->Text);
  PlainText = mmoPlainText1->Text;
  try {
    switch ((TEncryption) cbxCipher->ItemIndex) {
      case eBf      : CipherText = BFEncryptStringEx(PlainText, Key128, true);
                      break;
      case eBfCbc   : CipherText = BFEncryptStringCBCEx(PlainText, Key128, true);
                      break;
      case eDes     : CipherText = DESEncryptStringEx(PlainText, Key64, true);
                      break;
      case eDesCbc  : CipherText = DESEncryptStringCBCEx(PlainText, Key64, true);
                      break;
      case e3Des    : CipherText = TripleDESEncryptStringEx(PlainText, Key128, true);
                      break;
      case e3DesCbc : CipherText = TripleDESEncryptStringCBCEx(PlainText, Key128, true);
                      break;
      case eRdl     : CipherText = RDLEncryptStringEx(PlainText, Key128, 16, true);
                      break;
      case eRdlCbc  : CipherText = RDLEncryptStringCBCEx(PlainText, Key128, 16, true);
                      break;
    }
    mmoCipherText->Text = CipherText;
  }
  catch (...) {
  }  // swallow any errors
  Screen->Cursor = crDefault;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnDecryptClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  GenerateLMDKey(Key64, sizeof(Key64),   edtPassphrase->Text);
  GenerateLMDKey(Key128, sizeof(Key128), edtPassphrase->Text);
  GenerateLMDKey(Key192, sizeof(Key192), edtPassphrase->Text);
  GenerateLMDKey(Key256, sizeof(Key256), edtPassphrase->Text);
  CipherText = mmoCipherText->Text;
  try {
    switch ((TEncryption) cbxCipher->ItemIndex) {
      case eBf      : PlainText = BFEncryptStringEx(CipherText, Key128, false);
                      break;
      case eBfCbc   : PlainText = BFEncryptStringCBCEx(CipherText, Key128, false);
                      break;
      case eDes     : PlainText = DESEncryptStringEx(CipherText, Key64, false);
                      break;
      case eDesCbc  : PlainText = DESEncryptStringCBCEx(CipherText, Key64, false);
                      break;
      case e3Des    : PlainText = TripleDESEncryptStringEx(CipherText, Key128, false);
                      break;
      case e3DesCbc : PlainText = TripleDESEncryptStringCBCEx(CipherText, Key128, false);
                      break;
      case eRdl     : PlainText = RDLEncryptStringEx(CipherText, Key128, 16, false);
                      break;
      case eRdlCbc  : PlainText = RDLEncryptStringCBCEx(CipherText, Key128, 16, false);
                      break;
    }
    mmoPlainText2->Text = PlainText;
  }
  catch (...) {
  }  // swallow any errors
  Screen->Cursor = crDefault;
}
//---------------------------------------------------------------------------
