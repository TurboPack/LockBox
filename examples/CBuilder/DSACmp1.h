//---------------------------------------------------------------------------
#ifndef DSACmp1H
#define DSACmp1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include "LbAsym.hpp"
#include "LbCipher.hpp"
#include "LbClass.hpp"
#include "LbDSA.hpp"
#include "LbUtils.hpp"
#include <ComCtrls.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TLabel *Label1;
    TLabel *Label2;
    TLabel *Label3;
    TLabel *Label4;
    TLabel *Label5;
    TLabel *Label6;
    TLabel *Label7;
    TLabel *Label8;
    TLabel *Label9;
    TLabel *Label10;
    TLabel *Label11;
    TButton *btnGenParams;
    TMemo *mmoP;
    TMemo *mmoG;
    TMemo *mmoY;
    TEdit *edtMsg;
    TEdit *edtR;
    TEdit *edtS;
    TButton *btnSign;
    TEdit *edtQ;
    TEdit *edtX;
    TButton *btnVerify;
    TStatusBar *StatusBar1;
    TEdit *edtSeed;
    TEdit *edtXKey;
    TEdit *edtKKey;
    TButton *btnGenXY;
    TButton *btnSetParams;
    TButton *btnSetXY;
    TCheckBox *chkAbort;
    TLbDSA *LbDSA1;
    void __fastcall btnGenParamsClick(TObject *Sender);
    void __fastcall btnGenXYClick(TObject *Sender);
    void __fastcall btnSignClick(TObject *Sender);
    void __fastcall btnVerifyClick(TObject *Sender);
    void __fastcall btnSetParamsClick(TObject *Sender);
    void __fastcall btnSetXYClick(TObject *Sender);
    void __fastcall LbDSA1GetSeed(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1GetXKey(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1GetKKey(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1GetR(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1GetS(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1Progress(TObject *Sender, bool &Abort);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
