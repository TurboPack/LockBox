//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "RDLCmp1.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma resource "*.dfm"
TForm1 *Form1;
//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------

void __fastcall TForm1::FormCreate(TObject *Sender)
{
  cbxCipherMode->ItemIndex = Integer(LbRijndael1->CipherMode);
  cbxKeySize->ItemIndex = Integer(LbRijndael1->KeySize);
}
//---------------------------------------------------------------------------

void __fastcall TForm1::btnEncryptClick(TObject *Sender)
{
  LbRijndael1->GenerateKey(edtPassphrase->Text);
  mmoCipherText->Text = LbRijndael1->EncryptString(mmoPlainText1->Text);
  mmoPlainText2->Clear();
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnDecryptClick(TObject *Sender)
{
  LbRijndael1->GenerateKey(edtPassphrase->Text);
  mmoPlainText2->Text = LbRijndael1->DecryptString(mmoCipherText->Text);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::cbxCipherModeChange(TObject *Sender)
{
  LbRijndael1->CipherMode = TLbCipherMode(cbxCipherMode->ItemIndex);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::cbxKeySizeChange(TObject *Sender)
{
  LbRijndael1->KeySize = TLbKeySizeRDL(cbxKeySize->ItemIndex);
}
//---------------------------------------------------------------------------
