//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "ExHash1.h"
#pragma link "LbCipher.obj"
#pragma link "LbUtils.obj"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TForm1 *Form1;

enum THashMethod {hmMD5, hmSHA1, hmLMD, hmELF};

TMD5Digest  MD5Digest;
TSHA1Digest SHA1Digest;
int ELFDigest;
int LMDDigest;


//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::btnGoClick(TObject *Sender)
{
  switch ((THashMethod) rgHashMethod->ItemIndex) {
    case hmMD5 : StringHashMD5(MD5Digest, edtMessage->Text);
                 edtDigest->Text = BufferToHex(MD5Digest, sizeof(MD5Digest));
                 break;
    case hmSHA1 : StringHashSHA1(SHA1Digest, edtMessage->Text);
                  edtDigest->Text = BufferToHex(SHA1Digest, sizeof(SHA1Digest));
                  break;
    case hmLMD : StringHashLMD(&LMDDigest, sizeof(LMDDigest), edtMessage->Text);
                 edtDigest->Text = BufferToHex(&LMDDigest, sizeof(LMDDigest));
                 break;
    case hmELF : StringHashELF(ELFDigest, edtMessage->Text);
                 edtDigest->Text = BufferToHex(&ELFDigest, sizeof(ELFDigest));
                 break;
  }
}
//---------------------------------------------------------------------------

