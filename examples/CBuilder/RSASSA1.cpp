//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "RSASSA1.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbAsym"
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma link "LbUtils"
#pragma link "LbRSA"
#pragma resource "*.dfm"
TForm1 *Form1;

AnsiString sPass = "Signature verification: PASSED";
AnsiString sFail = "Signature verification: FAILED";

//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  cbxHashMethod->ItemIndex = (int) LbRSASSA1->HashMethod;
  cbxKeySize->ItemIndex = (int) LbRSASSA1->KeySize - 1;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnGenKeysClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Generating RSA key pair- this may take a while";
  try {
    LbRSASSA1->GenerateKeyPair();
  }
  __finally {
    Screen->Cursor = crDefault;
    StatusBar1->SimpleText = "";
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::cbxKeySizeChange(TObject *Sender)
{
  LbRSASSA1->KeySize = (TLbAsymKeySize) (cbxKeySize->ItemIndex + 1);
}
//---------------------------------------------------------------------------

void __fastcall TForm1::cbxHashMethodChange(TObject *Sender)
{
  LbRSASSA1->HashMethod = (TRSAHashMethod) cbxHashMethod->ItemIndex;
}
//---------------------------------------------------------------------------

void __fastcall TForm1::LbRSASSA1GetSignature(TObject *Sender,
      TRSASignatureBlock &Sig)
{
  HexToBuffer(mmoSignature->Text, Sig, sizeof(Sig));
}
//---------------------------------------------------------------------------

void __fastcall TForm1::btnSignClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Generating signature";
  try {
    LbRSASSA1->SignString(edtMsg->Text);
    mmoSignature->Text = LbRSASSA1->Signature->IntStr;
  }
  __finally {
    Screen->Cursor = crDefault;
    StatusBar1->SimpleText = "";
  }
}
//---------------------------------------------------------------------------

void __fastcall TForm1::btnVerifyClick(TObject *Sender)
{
  if (LbRSASSA1->VerifyString(edtMsg->Text))
    StatusBar1->SimpleText = " Signature verification: PASSED";
  else
    StatusBar1->SimpleText = " Signature verification: Failed";
}
//---------------------------------------------------------------------------

