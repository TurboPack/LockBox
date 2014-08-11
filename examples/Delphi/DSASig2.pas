unit DSASig2;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls;

type
  TdlgKeySize = class(TForm)
    Label9: TLabel;
    cbxKeySize: TComboBox;
    Label8: TLabel;
    Label5: TLabel;
    cbxIterations: TComboBox;
    btnOK: TButton;
    btnCancel: TButton;
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  dlgKeySize: TdlgKeySize;

implementation

{$R *.DFM}

procedure TdlgKeySize.FormCreate(Sender: TObject);
begin
  cbxKeySize.ItemIndex := 2;
  cbxIterations.ItemIndex := 2;
end;

end.
