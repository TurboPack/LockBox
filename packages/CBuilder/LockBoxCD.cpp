//---------------------------------------------------------------------------

#include <basepch.h>
#pragma hdrstop
USEFORMNS("..\..\source\LbDesign.pas", Lbdesign, LbAboutForm);
USEFORMNS("..\..\source\LbKeyEd1.pas", Lbkeyed1, frmSymmetricKey);
USEFORMNS("..\..\source\LbKeyEd2.pas", Lbkeyed2, frmRSAKeys);
//---------------------------------------------------------------------------
#pragma package(smart_init)
//---------------------------------------------------------------------------

//   Package source.
//---------------------------------------------------------------------------


#pragma argsused
int WINAPI DllEntryPoint(HINSTANCE hinst, unsigned long reason, void*)
{
    return 1;
}
//---------------------------------------------------------------------------
