//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "ExFile1.h"
#pragma link "LbCipher.obj"
#pragma link "LbProc.obj"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TForm1 *Form1;

TKey64  Key64;
TKey128 Key128;
TKey192 Key192;
TKey256 Key256;

enum TEncryption { eBf, eBfCbc, eDes, eDesCbc, e3Des, e3DesCbc, eRdl, eRdlCbc };


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
void __fastcall TForm1::btnGoClick(TObject *Sender)
{
  Screen->Cursor = crHourGlass;
  GenerateLMDKey(Key64, sizeof(Key64),   edtPassphrase->Text);
  GenerateLMDKey(Key128, sizeof(Key128), edtPassphrase->Text);
  GenerateLMDKey(Key192, sizeof(Key192), edtPassphrase->Text);
  GenerateLMDKey(Key256, sizeof(Key256), edtPassphrase->Text);
  try {
    switch ((TEncryption) cbxCipher->ItemIndex) {
      case eBf      : BFEncryptFile(edtInFile->Text, edtOutFile->Text, Key128, chkEncrypt->Checked);
                      break;
      case eBfCbc   : BFEncryptFileCBC(edtInFile->Text, edtOutFile->Text, Key128, chkEncrypt->Checked);
                      break;
      case eDes     : DESEncryptFile(edtInFile->Text, edtOutFile->Text, Key64, chkEncrypt->Checked);
                      break;
      case eDesCbc  : DESEncryptFileCBC(edtInFile->Text, edtOutFile->Text, Key64, chkEncrypt->Checked);
                      break;
      case e3Des    : TripleDESEncryptFile(edtInFile->Text, edtOutFile->Text, Key128, chkEncrypt->Checked);
                      break;
      case e3DesCbc : TripleDESEncryptFileCBC(edtInFile->Text, edtOutFile->Text, Key128, chkEncrypt->Checked);
                      break;
      case eRdl     : RDLEncryptFile(edtInFile->Text, edtOutFile->Text, Key128, 16, chkEncrypt->Checked);
                      break;
      case eRdlCbc  : RDLEncryptFileCBC(edtInFile->Text, edtOutFile->Text, Key128, 16, chkEncrypt->Checked);
                      break;
    }
  }
  catch (...) {
  }  // swallow any errors
  Screen->Cursor = crDefault;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::SpeedButton1Click(TObject *Sender)
{
  if (OpenDialog1->Execute())
    edtInFile->Text = OpenDialog1->FileName;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::SpeedButton2Click(TObject *Sender)
{
  if (SaveDialog1->Execute())
    edtOutFile->Text = SaveDialog1->FileName;
}
//---------------------------------------------------------------------------
