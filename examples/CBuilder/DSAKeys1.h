//---------------------------------------------------------------------------
#ifndef DSAKeys1H
#define DSAKeys1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include "LbAsym.hpp"
#include "LbCipher.hpp"
#include "LbClass.hpp"
#include "LbDSA.hpp"
#include <ComCtrls.hpp>
#include <Dialogs.hpp>
//---------------------------------------------------------------------------
class TfrmDSAKeys : public TForm
{
__published:	// IDE-managed Components
    TGroupBox *GroupBox4;
    TLabel *Label5;
    TLabel *Label8;
    TLabel *Label9;
    TButton *btnCreateKeys;
    TEdit *edtIterations;
    TButton *btnClear;
    TComboBox *cbxKeySize;
    TGroupBox *GroupBox1;
    TLabel *Label6;
    TLabel *Label1;
    TLabel *Label2;
    TLabel *Label10;
    TLabel *Label11;
    TButton *btnLoadPublic;
    TButton *btnSavePublic;
    TEdit *edtPublicPhrase;
    TEdit *edtPubQ;
    TMemo *mmoPubP;
    TMemo *mmoPubG;
    TMemo *mmoPubY;
    TGroupBox *GroupBox2;
    TLabel *Label7;
    TLabel *Label3;
    TLabel *Label4;
    TLabel *Label12;
    TLabel *Label13;
    TButton *btnLoadPrivate;
    TButton *btnSavePrivate;
    TEdit *edtPrivatePhrase;
    TEdit *edtPriQ;
    TMemo *mmoPriP;
    TMemo *mmoPriG;
    TEdit *edtPriX;
    TStatusBar *StatusBar1;
    TOpenDialog *dlgOpenASN;
    TSaveDialog *dlgSaveASN;
    TLbDSA *LbDSA1;
    void __fastcall btnCreateKeysClick(TObject *Sender);
    void __fastcall btnLoadPublicClick(TObject *Sender);
    void __fastcall btnSavePublicClick(TObject *Sender);
    void __fastcall btnLoadPrivateClick(TObject *Sender);
    void __fastcall btnSavePrivateClick(TObject *Sender);
    void __fastcall btnClearClick(TObject *Sender);
    void __fastcall FormCreate(TObject *Sender);
private:	// User declarations
    void __fastcall UpdatePrivateKeyFields();
    void __fastcall UpdatePublicKeyFields();
public:		// User declarations
    __fastcall TfrmDSAKeys(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TfrmDSAKeys *frmDSAKeys;
//---------------------------------------------------------------------------
#endif
