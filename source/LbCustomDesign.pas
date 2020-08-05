unit LbCustomDesign;

interface

procedure Register;

implementation

uses
  System.Classes, LbClass, lbRSA, LbDSA;

procedure Register;
begin
  RegisterComponents('LockBox',
                     [TLbBlowfish,
                      TLbDES,
                      TLb3DES,
                      TLbRijndael,
                      TLbRSA,
                      TLbMD5,
                      TLbSHA1,
                      TLbDSA,
                      TLbRSASSA]
                      );
end;

end.
