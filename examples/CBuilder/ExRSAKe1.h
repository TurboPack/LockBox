//---------------------------------------------------------------------------
#ifndef ExRSAKe1H
#define ExRSAKe1H
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <ComCtrls.hpp>
#include <Dialogs.hpp>
#include <ExtCtrls.hpp>
#include <LbAsym.hpp>
#include <LbRSA.hpp>
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
    TGroupBox *GroupBox4;
    TLabel *Label5;
    TButton *btnCreateKeys;
    TButton *btnFreeKeys;
    TEdit *edtIterations;
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
    TLabel *Label8;
    TComboBox *cbxKeySize;
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall btnCreateKeysClick(TObject *Sender);
    void __fastcall btnFreeKeysClick(TObject *Sender);
    void __fastcall btnLoadPublicClick(TObject *Sender);
    void __fastcall btnSavePublicClick(TObject *Sender);
    void __fastcall btnLoadPrivateClick(TObject *Sender);
    void __fastcall btnSavePrivateClick(TObject *Sender);
private:	// User declarations
    void __fastcall FreeKey(TLbRSAKey *Key);
    void __fastcall CreateKey(TLbRSAKey *Key);
public:		// User declarations
    __fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
