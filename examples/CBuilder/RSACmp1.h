//---------------------------------------------------------------------------
#ifndef RSACmp1H
#define RSACmp1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include "LbAsym.hpp"
#include "LbCipher.hpp"
#include "LbClass.hpp"
#include "LbRSA.hpp"
#include <ComCtrls.hpp>
#include <Dialogs.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TLabel *Label5;
    TLabel *Label7;
    TLabel *Label6;
    TButton *btnEncrypt;
    TButton *btnDecrypt;
    TMemo *mmoPlainText1;
    TMemo *mmoCipherText;
    TMemo *mmoPlainText2;
    TButton *btnGenKeys;
    TStatusBar *StatusBar1;
    TLbRSA *LbRSA1;
    TLabel *Label1;
    TComboBox *cbxKeySize;
    void __fastcall btnEncryptClick(TObject *Sender);
    void __fastcall btnDecryptClick(TObject *Sender);
    void __fastcall btnGenKeysClick(TObject *Sender);
    
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall cbxKeySizeChange(TObject *Sender);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
