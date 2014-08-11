//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "DSASig1.h"
#include "DSASig2.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbAsym"
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma link "LbDSA"
#pragma link "LbUtils"
#pragma link "DSASig2"
#pragma resource "*.dfm"
TfrmDSASig *frmDSASig;
//---------------------------------------------------------------------------
__fastcall TfrmDSASig::TfrmDSASig(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::UpdatePrivateKeyFields()
{
  edtPriQ->Text       = LbDSA1->PrivateKey->QAsString;
  mmoPriP->Lines->Text = LbDSA1->PrivateKey->PAsString;
  mmoPriG->Lines->Text = LbDSA1->PrivateKey->GAsString;
  edtPriX->Text       = LbDSA1->PrivateKey->XAsString;
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::UpdatePublicKeyFields()
{
  edtPubQ->Text       = LbDSA1->PublicKey->QAsString;
  mmoPubP->Lines->Text = LbDSA1->PublicKey->PAsString;
  mmoPubG->Lines->Text = LbDSA1->PublicKey->GAsString;
  mmoPubY->Lines->Text = LbDSA1->PublicKey->YAsString;
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuFileOpenClick(TObject *Sender)
{
  if (dlgOpenTxt->Execute())
  {
    mnuFileCloseClick(0);
    mmoMsg->Lines->LoadFromFile(dlgOpenTxt->FileName);
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuFileSignClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Signing message";
  try
  {
    LbDSA1->SignString(mmoMsg->Lines->Text);
    edtR->Text = LbDSA1->SignatureR->IntStr;
    edtS->Text = LbDSA1->SignatureS->IntStr;
    StatusBar1->SimpleText = "";
  }
  __finally
  {
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuFileVerifyClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Verifying signature";
  try
  {
    if (LbDSA1->VerifyString(mmoMsg->Lines->Text))
      StatusBar1->SimpleText = " Verification PASSED";
    else
      StatusBar1->SimpleText = " Verification FAILED";
  }
  __finally
  {
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuFileCloseClick(TObject *Sender)
{
  mmoMsg->Clear();
  edtR->Text = "";
  edtS->Text = "";
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuFileExitClick(TObject *Sender)
{
  Close();
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysGenerateClick(TObject *Sender)
{
  dlgKeySize = new TdlgKeySize(Application);
  try
  {
    if (dlgKeySize->ShowModal() == mrOk)
    {
      LbDSA1->KeySize = (TLbAsymKeySize) dlgKeySize->cbxKeySize->ItemIndex;
      LbDSA1->PrimeTestIterations = (unsigned char) ((dlgKeySize->cbxIterations->ItemIndex + 1) * 5);
    }
    else
      return;
  }
  __finally
  {
     dlgKeySize->Free();
  }

  mnuDSAKeysPubClearClick(0);
  mnuDSAKeysPriClearClick(0);
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = " Generating DSA public/private keys - this may take a while";
  try
  {
    LbDSA1->GenerateKeyPair();
    UpdatePrivateKeyFields();
    UpdatePublicKeyFields();
    StatusBar1->SimpleText = "";
    Screen->Cursor = crDefault;
  }
  catch (...)
  {
    StatusBar1->SimpleText = " DSA parameter failure";
    Screen->Cursor = crDefault;
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysPubSaveClick(TObject *Sender)
{
  if (dlgSaveASN->Execute())
    LbDSA1->PublicKey->StoreToFile(dlgSaveASN->FileName);
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysPriSaveClick(TObject *Sender)
{
  if (dlgSaveASN->Execute())
    LbDSA1->PrivateKey->StoreToFile(dlgSaveASN->FileName);
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysPubLoadClick(TObject *Sender)
{
  if (dlgOpenASN->Execute())
  {
    LbDSA1->PublicKey->LoadFromFile(dlgOpenASN->FileName);
    UpdatePublicKeyFields();
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysPriLoadClick(TObject *Sender)
{
  if (dlgOpenASN->Execute())
  {
    LbDSA1->PrivateKey->LoadFromFile(dlgOpenASN->FileName);
    UpdatePrivateKeyFields();
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysPubClearClick(TObject *Sender)
{
  LbDSA1->PublicKey->Clear();
  UpdatePublicKeyFields();
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::mnuDSAKeysPriClearClick(TObject *Sender)
{
  LbDSA1->PrivateKey->Clear();
  UpdatePrivateKeyFields();
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::LbDSA1GetR(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtR->Text, &Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::LbDSA1GetS(TObject *Sender, TLbDSABlock &Block)
{
  HexToBuffer(edtS->Text, &Block, sizeof(Block));
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSASig::LbDSA1Progress(TObject *Sender, bool &Abort)
{
  Application->ProcessMessages();
}
//---------------------------------------------------------------------------
