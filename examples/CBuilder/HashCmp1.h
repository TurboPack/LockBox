//---------------------------------------------------------------------------
#ifndef HashCmp1H
#define HashCmp1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include "LbCipher.hpp"
#include "LbClass.hpp"
#include "LbUtils.hpp"
#include <Dialogs.hpp>
#include <ExtCtrls.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TButton *btnHashFile;
    TEdit *edtHash;
    TRadioGroup *rgHashMethod;
    TButton *btnHashString;
    TLbMD5 *LbMD51;
    TLbSHA1 *LbSHA11;
    TOpenDialog *OpenDialog1;
    void __fastcall btnHashFileClick(TObject *Sender);
    void __fastcall btnHashStringClick(TObject *Sender);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
