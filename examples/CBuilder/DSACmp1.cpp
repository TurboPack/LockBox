//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "DSACmp1.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbAsym"
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma link "LbDSA"
#pragma resource "*.dfm"
TForm1 *Form1;
//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnGenParamsClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Generating DSA parameters - this may take a while";

  try {
    if (LbDSA1->GeneratePQG()) {
      edtQ->Text = LbDSA1->PrivateKey->QAsString;
      mmoP->Lines->Text = LbDSA1->PrivateKey->PAsString;
      mmoG->Lines->Text = LbDSA1->PrivateKey->GAsString;
      StatusBar1->SimpleText = "";
    }
    else
      StatusBar1->SimpleText = " DSA parameter failure";
  }
  __finally {
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnGenXYClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Generating X and Y";

  try {
    LbDSA1->GenerateXY();
    edtX->Text = LbDSA1->PrivateKey->XAsString;
    mmoY->Lines->Text = LbDSA1->PublicKey->YAsString;
    StatusBar1->SimpleText = "";
  }
  __finally {
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSignClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Signing message";

  try {
    LbDSA1->SignString(edtMsg->Text);
    edtR->Text = LbDSA1->SignatureR->IntStr;
    edtS->Text = LbDSA1->SignatureS->IntStr;
    StatusBar1->SimpleText = "";
  }
  __finally {
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnVerifyClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Verifying signature";

  try {
    if (LbDSA1->VerifyString(edtMsg->Text))
      StatusBar1->SimpleText = " Verification PASSED";
    else
      StatusBar1->SimpleText = " Verification FAILED";
  }
  __finally {
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSetParamsClick(TObject *Sender)
{
  LbDSA1->PrivateKey->QAsString = edtQ->Text;
  LbDSA1->PrivateKey->PAsString = mmoP->Lines->Text;
  LbDSA1->PrivateKey->GAsString = mmoG->Lines->Text;
  LbDSA1->PublicKey->QAsString = edtQ->Text;
  LbDSA1->PublicKey->PAsString = mmoP->Lines->Text;
  LbDSA1->PublicKey->GAsString = mmoG->Lines->Text;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnSetXYClick(TObject *Sender)
{
  LbDSA1->PrivateKey->XAsString = edtX->Text;
  LbDSA1->PublicKey->YAsString = mmoY->Text;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::LbDSA1GetSeed(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtSeed->Text, Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TForm1::LbDSA1GetXKey(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtXKey->Text, Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TForm1::LbDSA1GetKKey(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtKKey->Text, Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TForm1::LbDSA1GetR(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtR->Text, Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TForm1::LbDSA1GetS(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtS->Text, Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TForm1::LbDSA1Progress(TObject *Sender, bool &Abort)
{
  Application->ProcessMessages();
  Abort = chkAbort->Checked;
}
//---------------------------------------------------------------------------
