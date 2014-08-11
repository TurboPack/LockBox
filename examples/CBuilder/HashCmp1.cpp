//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "HashCmp1.h"
#pragma link "LbUtils.obj"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "LbCipher"
#pragma link "LbClass"
#pragma resource "*.dfm"
TForm1 *Form1;

TMD5Digest  MD5Digest;
TSHA1Digest SHA1Digest;

//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnHashFileClick(TObject *Sender)
{
  if (OpenDialog1->Execute()) {
    switch (rgHashMethod->ItemIndex) {
      case 0 : LbMD51->HashFile(OpenDialog1->FileName);
               LbMD51->GetDigest(MD5Digest);
               edtHash->Text = BufferToHex(MD5Digest, sizeof(MD5Digest));
               break;
      case 1 : LbSHA11->HashFile(OpenDialog1->FileName);
               LbSHA11->GetDigest(SHA1Digest);
               edtHash->Text = BufferToHex(SHA1Digest, sizeof(SHA1Digest));
               break;
    }
  }
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnHashStringClick(TObject *Sender)
{
  AnsiString S = "";
  if (InputQuery("HashCmp", "Enter String", S)) {
    switch (rgHashMethod->ItemIndex) {
      case 0 : LbMD51->HashString(S);
               LbMD51->GetDigest(MD5Digest);
               edtHash->Text = BufferToHex(MD5Digest, sizeof(MD5Digest));
               break;
      case 1 : LbSHA11->HashString(S);
               LbSHA11->GetDigest(SHA1Digest);
               edtHash->Text = BufferToHex(SHA1Digest, sizeof(SHA1Digest));
               break;
    }
  }
}
//---------------------------------------------------------------------------
