//---------------------------------------------------------------------------
#ifndef RSAKeys1H
#define RSAKeys1H
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
#include <ExtCtrls.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TGroupBox *GroupBox4;
    TLabel *Label5;
    TLabel *Label8;
    TButton *btnCreateKeys;
    TEdit *edtIterations;
    TButton *btnClear;
    TGroupBox *GroupBox1;
    TLabel *Label1;
    TLabel *Label2;
    TLabel *Label6;
    TEdit *edtPublicE;
    TEdit *edtPublicM;
    TButton *btnLoadPublic;
    TButton *btnSavePublic;
    TEdit *edtPublicPhrase;
    TGroupBox *GroupBox2;
    TLabel *Label3;
    TLabel *Label4;
    TLabel *Label7;
    TEdit *edtPrivateE;
    TEdit *edtPrivateM;
    TButton *btnLoadPrivate;
    TButton *btnSavePrivate;
    TEdit *edtPrivatePhrase;
    TStatusBar *StatusBar1;
    TOpenDialog *OpenDialog1;
    TSaveDialog *SaveDialog1;
    TLbRSA *LbRSA1;
    TLabel *Label9;
    TComboBox *cbxKeySize;
    void __fastcall btnCreateKeysClick(TObject *Sender);
    void __fastcall btnLoadPublicClick(TObject *Sender);
    void __fastcall btnSavePublicClick(TObject *Sender);
    void __fastcall btnLoadPrivateClick(TObject *Sender);
    void __fastcall btnSavePrivateClick(TObject *Sender);
    void __fastcall btnClearClick(TObject *Sender);
    void __fastcall FormCreate(TObject *Sender);
private:	// User declarations
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
