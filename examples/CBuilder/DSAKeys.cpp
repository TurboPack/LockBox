//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
USERES("DSAKeys.res");
USEFORM("DSAKeys1.cpp", frmDSAKeys);
//---------------------------------------------------------------------------
WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    try
    {
        Application->Initialize();
        Application->CreateForm(__classid(TfrmDSAKeys), &frmDSAKeys);
        Application->Run();
    }
    catch (Exception &exception)
    {
        Application->ShowException(&exception);
    }
    return 0;
}
//---------------------------------------------------------------------------
