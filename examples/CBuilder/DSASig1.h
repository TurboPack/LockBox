//---------------------------------------------------------------------------
#ifndef DSASig1H
#define DSASig1H
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
#include <Dialogs.hpp>
#include <Menus.hpp>
//---------------------------------------------------------------------------
class TfrmDSASig : public TForm
{
__published:	// IDE-managed Components
    TStatusBar *StatusBar1;
    TGroupBox *GroupBox1;
    TLabel *Label1;
    TLabel *Label2;
    TLabel *Label3;
    TLabel *Label4;
    TEdit *edtPriQ;
    TMemo *mmoPriP;
    TMemo *mmoPriG;
    TEdit *edtPriX;
    TGroupBox *GroupBox2;
    TLabel *Label5;
    TLabel *Label9;
    TLabel *Label10;
    TLabel *Label11;
    TEdit *edtPubQ;
    TMemo *mmoPubP;
    TMemo *mmoPubG;
    TMemo *mmoPubY;
    TGroupBox *GroupBox3;
    TLabel *Label7;
    TLabel *Label8;
    TEdit *edtR;
    TEdit *edtS;
    TGroupBox *GroupBox4;
    TMemo *mmoMsg;
    TLbDSA *LbDSA1;
    TMainMenu *mnuMain;
    TMenuItem *mnuFile;
    TMenuItem *mnuFileOpen;
    TMenuItem *mnuFileSign;
    TMenuItem *mnuFileVerify;
    TMenuItem *mnuFileClose;
    TMenuItem *N1;
    TMenuItem *mnuFileExit;
    TMenuItem *mnuDSAKeys;
    TMenuItem *mnuDSAKeysGenerate;
    TMenuItem *mnuDSAKeysPub;
    TMenuItem *mnuDSAKeysPubSave;
    TMenuItem *mnuDSAKeysPubLoad;
    TMenuItem *mnuDSAKeysPubClear;
    TMenuItem *mnuDSAKeysPri;
    TMenuItem *mnuDSAKeysPriSave;
    TMenuItem *mnuDSAKeysPriLoad;
    TMenuItem *mnuDSAKeysPriClear;
    TOpenDialog *dlgOpenTxt;
    TOpenDialog *dlgOpenASN;
    TSaveDialog *dlgSaveASN;
    void __fastcall mnuFileOpenClick(TObject *Sender);
    void __fastcall mnuFileSignClick(TObject *Sender);
    void __fastcall mnuFileVerifyClick(TObject *Sender);
    void __fastcall mnuFileCloseClick(TObject *Sender);
    void __fastcall mnuFileExitClick(TObject *Sender);
    void __fastcall mnuDSAKeysGenerateClick(TObject *Sender);
    void __fastcall mnuDSAKeysPubSaveClick(TObject *Sender);
    void __fastcall mnuDSAKeysPriSaveClick(TObject *Sender);
    void __fastcall mnuDSAKeysPubLoadClick(TObject *Sender);
    void __fastcall mnuDSAKeysPriLoadClick(TObject *Sender);
    void __fastcall mnuDSAKeysPubClearClick(TObject *Sender);
    void __fastcall mnuDSAKeysPriClearClick(TObject *Sender);
    void __fastcall LbDSA1GetR(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1GetS(TObject *Sender, TLbDSABlock &Block);
    void __fastcall LbDSA1Progress(TObject *Sender, bool &Abort);
private:	// User declarations
    void __fastcall UpdatePrivateKeyFields();
    void __fastcall UpdatePublicKeyFields();
public:		// User declarations
    __fastcall TfrmDSASig(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TfrmDSASig *frmDSASig;
//---------------------------------------------------------------------------
#endif
