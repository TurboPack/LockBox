//---------------------------------------------------------------------------
#ifndef RSASSA1H
#define RSASSA1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include "LbAsym.hpp"
#include "LbCipher.hpp"
#include "LbClass.hpp"
#include "LbRSA.hpp"
#include "LbUtils.hpp"
#include <ComCtrls.hpp>
#include <Dialogs.hpp>
#include <ExtCtrls.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TLabel *Label1;
    TLabel *Label4;
    TLabel *Label3;
    TStatusBar *StatusBar1;
    TMemo *mmoSignature;
    TGroupBox *GroupBox1;
    TLabel *Label2;
    TComboBox *cbxKeySize;
    TButton *btnGenKeys;
    TEdit *edtMsg;
    TButton *btnSign;
    TButton *btnVerify;
    TComboBox *cbxHashMethod;
    TLbRSASSA *LbRSASSA1;void __fastcall FormCreate(TObject *Sender);
    void __fastcall btnGenKeysClick(TObject *Sender);
    void __fastcall cbxKeySizeChange(TObject *Sender);
    void __fastcall cbxHashMethodChange(TObject *Sender);
    void __fastcall LbRSASSA1GetSignature(TObject *Sender,
          TRSASignatureBlock &Sig);
    void __fastcall btnSignClick(TObject *Sender);
    void __fastcall btnVerifyClick(TObject *Sender);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
