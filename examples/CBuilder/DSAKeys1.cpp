//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "DSAKeys1.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbAsym"
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma link "LbDSA"
#pragma resource "*.dfm"
TfrmDSAKeys *frmDSAKeys;
//---------------------------------------------------------------------------
__fastcall TfrmDSAKeys::TfrmDSAKeys(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::UpdatePrivateKeyFields()
{
  edtPriQ->Text        = LbDSA1->PrivateKey->QAsString;
  mmoPriP->Lines->Text = LbDSA1->PrivateKey->PAsString;
  mmoPriG->Lines->Text = LbDSA1->PrivateKey->GAsString;
  edtPriX->Text        = LbDSA1->PrivateKey->XAsString;
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::UpdatePublicKeyFields()
{
  edtPubQ->Text        = LbDSA1->PublicKey->QAsString;
  mmoPubP->Lines->Text = LbDSA1->PublicKey->PAsString;
  mmoPubG->Lines->Text = LbDSA1->PublicKey->GAsString;
  mmoPubY->Lines->Text = LbDSA1->PublicKey->YAsString;
}
//---------------------------------------------------------------------------

void __fastcall TfrmDSAKeys::btnCreateKeysClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  StatusBar1->SimpleText = "Generating key pair, this may take a while";
  try
  {
    LbDSA1->PrimeTestIterations = (unsigned char) StrToIntDef(edtIterations->Text, 20);
    LbDSA1->KeySize = TLbAsymKeySize(cbxKeySize->ItemIndex);
    LbDSA1->GenerateKeyPair();
    UpdatePrivateKeyFields();
    UpdatePublicKeyFields();
  }
  __finally
  {
    Screen->Cursor = crDefault;
    StatusBar1->SimpleText = "";
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::btnLoadPublicClick(TObject *Sender)
{
  if (dlgOpenASN->Execute())
  {
    LbDSA1->PublicKey->Passphrase = edtPublicPhrase->Text;
    LbDSA1->PublicKey->LoadFromFile(dlgOpenASN->FileName);
    UpdatePublicKeyFields();
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::btnSavePublicClick(TObject *Sender)
{
  if (dlgSaveASN->Execute())
  {
    LbDSA1->PublicKey->Passphrase = edtPublicPhrase->Text;
    LbDSA1->PublicKey->StoreToFile(dlgSaveASN->FileName);
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::btnLoadPrivateClick(TObject *Sender)
{
  if (dlgOpenASN->Execute())
  {
    LbDSA1->PrivateKey->Passphrase = edtPrivatePhrase->Text;
    LbDSA1->PrivateKey->LoadFromFile(dlgOpenASN->FileName);
    UpdatePrivateKeyFields();
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::btnSavePrivateClick(TObject *Sender)
{
  if (dlgSaveASN->Execute())
  {
    LbDSA1->PrivateKey->Passphrase = edtPrivatePhrase->Text;
    LbDSA1->PrivateKey->StoreToFile(dlgSaveASN->FileName);
  }
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::btnClearClick(TObject *Sender)
{
  LbDSA1->PublicKey->Clear();
  LbDSA1->PrivateKey->Clear();
  UpdatePublicKeyFields();
  UpdatePrivateKeyFields();
}
//---------------------------------------------------------------------------
void __fastcall TfrmDSAKeys::FormCreate(TObject *Sender)
{
  cbxKeySize->ItemIndex = (int) LbDSA1->KeySize;
}
//---------------------------------------------------------------------------
