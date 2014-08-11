//---------------------------------------------------------------------------
#ifndef ExStrin1H
#define ExStrin1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <LbCipher.hpp>
#include <LbString.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TLabel *Label4;
    TLabel *Label5;
    TLabel *Label7;
    TLabel *Label6;
    TLabel *Label1;
    TButton *btnEncrypt;
    TButton *btnDecrypt;
    TComboBox *cbxCipher;
    TMemo *mmoPlainText1;
    TMemo *mmoCipherText;
    TMemo *mmoPlainText2;
    TEdit *edtPassphrase;
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall btnEncryptClick(TObject *Sender);
    void __fastcall btnDecryptClick(TObject *Sender);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
