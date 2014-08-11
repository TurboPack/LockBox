program DSAKeys;

uses
  Forms,
  DSAKeys1 in 'DSAKeys1.pas' {frmDSAKeys},
  LbUtils in '..\..\LbUtils.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmDSAKeys, frmDSAKeys);
  Application.Run;
end.
