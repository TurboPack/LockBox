(* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is TurboPower LockBox
 *
 * The Initial Developer of the Original Code is
 * TurboPower Software
 *
 * Portions created by the Initial Developer are Copyright (C) 1997-2002
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s): 
 *
 * ***** END LICENSE BLOCK ***** *)
{*********************************************************}
{*                  LBBIGINT.PAS 2.08                    *}
{*     Copyright (c) 2002 TurboPower Software Co         *}
{*                 All rights reserved.                  *}
{*********************************************************}

{$I LockBox.inc}

unit LbBigInt;
  {-bigInteger math routines}

interface

uses
{$IFDEF MSWINDOWS}
  Windows,
{$ENDIF}
{$IFDEF POSIX}
  Types,
{$ENDIF}
{$IFDEF UsingCLX}
  Types,
{$ENDIF}
  Sysutils,
  LbRandom;

const
  cLESS_THAN    = shortInt(-1);
  cEQUAL_TO     = shortInt(0);
  cGREATER_THAN = shortInt(1);
  cPOSITIVE     = True;
  cNEGATIVE     = False;

{ LbInteger record }
type
  LbIntBuf = packed record
    dwLen : integer;                                                      {!!03}
    pBuf  : pByte;
  end;

  LbInteger = packed record
    bSign : Boolean;
    dwUsed : integer;                                                     {!!03}
    IntBuf : LbIntBuf;
  end;

{ TLbBigInt }
type
  TLbBigInt = class
    protected {private}
      FI : LbInteger;
      procedure setSign(value : Boolean);
      function getSign : Boolean;
      function GetSize : integer;                                         {!!03}
      function GetIntStr : string;
      function GetIntBuf : pByte;
    public
      constructor Create(ALen : Integer);
      destructor Destroy; override;

      procedure Add(I2 : TLbBigInt);
      procedure Subtract(I2 : TLbBigInt);
      procedure Multiply(I2 : TLbBigInt);
      procedure Divide(I2 : TLbBigInt);
      procedure Modulus(I2 : TLbBigInt);
      function ModInv(Modulus : TLbBigInt) : Boolean;
      procedure PowerAndMod(Exponent : TLbBigInt; modulus : TLbBigInt);

      procedure AddByte(b : byte);
      procedure SubtractByte(b : byte);
      procedure MultiplyByte(b : byte);
      procedure DivideByte(b : byte);
      procedure ModByte(b : byte);

      procedure Clear;
      procedure Trim;
      function Compare(I2 : TLbBigInt) : ShortInt;
      function IsZero : Boolean;
      function IsOne : Boolean;
      function IsOdd : Boolean;
      function IsEven : Boolean;
      function IsComposite(Iterations : Cardinal) : Boolean;
      function Abs(I2 : TLbBigInt) : ShortInt;
      procedure ReverseBits;
      procedure ReverseBytes;
      function GetBit(bit : Integer) : Boolean;
      procedure Shr_(_shr : Integer);
      procedure Shl_(_shl : Integer);
      procedure OR_(I2 : TLbBigInt);
      procedure XOR_(I2 : TLbBigInt);

      procedure RandomBytes(Count : Cardinal);
      procedure RandomPrime(Iterations : Byte);
      procedure RandomSimplePrime;

      procedure Copy(I2 : TLbBigInt);
      procedure CopyLen(I2 : TLbBigInt; Len : Integer);
      procedure CopyByte(b : byte);
      procedure CopyWord(w : word);
      procedure CopyDWord(d : dword);
      procedure CopyBuffer(const Buf; BufLen : Integer);

      procedure Append(I : TLbBigInt);
      procedure AppendByte(b : byte);
      procedure AppendWord(w : word);
      procedure AppendDWord(d : dword);
      procedure AppendBuffer(const Buf; BufLen : Integer);

      procedure Prepend(I : TLbBigInt);
      procedure PrependByte(b : byte);
      procedure PrependWord(w : word);
      procedure PrependDWord(d : dword);
      procedure PrependBuffer(const Buf; BufLen : Integer);

      function ToBuffer(var Buf; BufLen : Integer) : integer;
      function GetByteValue( place : integer ) : Byte;

      property Sign : Boolean
        read getSign write setSign;
      property Int : LbInteger
        read FI;
      property IntBuf : pByte
        read GetIntBuf;
      property IntStr : string
        read GetIntStr;
      property Size : integer                                             {!!03}
        read GetSize;

end;


implementation

uses
  {$IFDEF Debugging} Dialogs, {$ENDIF}
  LbUtils, LbConst;

const { misc local constants }
  cBYTE_POSSIBLE_VALUES  = 256;
  cDEFAULT_PRECISION     = 64;
  cUSE_DEFAULT_PRECISION = 0;
  cDEFAULT_SIGN          = cPOSITIVE;
  cDEFAULT_USED          = 0;
  cAPPEND_ARRAY          = 0;
  cPREPEND_ARRAY         = 1;
  cDEFAULT_MAX_PRECISION = 256;


const { simple prime table }
  cTotalSimplePrimes      = (258 * 8);
  cTotalSimpleBytePrimes  = 53;  { %80 elimination }
  cTotalSimple2KPrimes    = 303;

type
  pBiByteArray = ^TBiByteArray;
  pBiWordArray = ^TBiWordArray;
//  TBiByteArray = array[0..65535] of Byte;
  TBiByteArray = array[0..pred(maxint)] of Byte;
  TBiWordArray = array[0..pred(maxint div 2 )] of word;
const
  cMaxBigIntSize = SizeOf( TByteArray );

const
  { source :
    http://www.geocities.com/ResearchTriangle/Thinktank/2434/prime/primenumbers.html }
  SimplePrimes : array[ 0..pred(cTotalSimplePrimes)] of DWord = (       {!!.01}
    2    , 3    , 5    , 7    , 11   , 13   , 17   , 19   ,   // 1
    23   , 29   , 31   , 37   , 41   , 43   , 47   , 53   ,   // 2
    59   , 61   , 67   , 71   , 73   , 79   , 83   , 89   ,   // 3
    97   , 101  , 103  , 107  , 109  , 113  , 127  , 131  ,   // 4
    137  , 139  , 149  , 151  , 157  , 163  , 167  , 173  ,   // 5
    179  , 181  , 191  , 193  , 197  , 199  , 211  , 223  ,   // 6
    227  , 229  , 233  , 239  , 241  , 251  , 257  , 263  ,   // 7  < 256 = 53
    269  , 271  , 277  , 281  , 283  , 293  , 307  , 311  ,   // 8
    313  , 317  , 331  , 337  , 347  , 349  , 353  , 359  ,   // 9

    367  , 373  , 379  , 383  , 389  , 397  , 401  , 409  ,   // 10
    419  , 421  , 431  , 433  , 439  , 443  , 449  , 457  ,   // 11
    461  , 463  , 467  , 479  , 487  , 491  , 499  , 503  ,   // 12
    509  , 521  , 523  , 541  , 547  , 557  , 563  , 569  ,   // 13
    571  , 577  , 587  , 593  , 599  , 601  , 607  , 613  ,   // 14
    617  , 619  , 631  , 641  , 643  , 647  , 653  , 659  ,   // 15
    661  , 673  , 677  , 683  , 691  , 701  , 709  , 719  ,   // 16
    727  , 733  , 739  , 743  , 751  , 757  , 761  , 769  ,   // 17
    773  , 787  , 797  , 809  , 811  , 821  , 823  , 827  ,   // 18
    829  , 839  , 853  , 857  , 859  , 863  , 877  , 881  ,   // 19

    883  , 887  , 907  , 911  , 919  , 929  , 937  , 941  ,   // 20
    947  , 953  , 967  , 971  , 977  , 983  , 991  , 997  ,   // 21
    1009 , 1013 , 1019 , 1021 , 1031 , 1033 , 1039 , 1049 ,   // 22
    1051 , 1061 , 1063 , 1069 , 1087 , 1091 , 1093 , 1097 ,   // 23
    1103 , 1109 , 1117 , 1123 , 1129 , 1151 , 1153 , 1163 ,   // 24
    1171 , 1181 , 1187 , 1193 , 1201 , 1213 , 1217 , 1223 ,   // 25
    1229 , 1231 , 1237 , 1249 , 1259 , 1277 , 1279 , 1283 ,   // 26
    1289 , 1291 , 1297 , 1301 , 1303 , 1307 , 1319 , 1321 ,   // 27
    1327 , 1361 , 1367 , 1373 , 1381 , 1399 , 1409 , 1423 ,   // 28
    1427 , 1429 , 1433 , 1439 , 1447 , 1451 , 1453 , 1459 ,   // 29

    1471 , 1481 , 1483 , 1487 , 1489 , 1493 , 1499 , 1511 ,   // 30
    1523 , 1531 , 1543 , 1549 , 1553 , 1559 , 1567 , 1571 ,   // 31
    1579 , 1583 , 1597 , 1601 , 1607 , 1609 , 1613 , 1619 ,   // 32
    1621 , 1627 , 1637 , 1657 , 1663 , 1667 , 1669 , 1693 ,   // 33
    1697 , 1699 , 1709 , 1721 , 1723 , 1733 , 1741 , 1747 ,   // 34
    1753 , 1759 , 1777 , 1783 , 1787 , 1789 , 1801 , 1811 ,   // 35
    1823 , 1831 , 1847 , 1861 , 1867 , 1871 , 1873 , 1877 ,   // 36
    1879 , 1889 , 1901 , 1907 , 1913 , 1931 , 1933 , 1949 ,   // 37
    1951 , 1973 , 1979 , 1987 , 1993 , 1997 , 1999 , 2003 ,   // 38 < 2000 = 303
    2011 , 2017 , 2027 , 2029 , 2039 , 2053 , 2063 , 2069 ,   // 39

    2081 , 2083 , 2087 , 2089 , 2099 , 2111 , 2113 , 2129 ,   // 40
    2131 , 2137 , 2141 , 2143 , 2153 , 2161 , 2179 , 2203 ,   // 41
    2207 , 2213 , 2221 , 2237 , 2239 , 2243 , 2251 , 2267 ,   // 42
    2269 , 2273 , 2281 , 2287 , 2293 , 2297 , 2309 , 2311 ,   // 43
    2333 , 2339 , 2341 , 2347 , 2351 , 2357 , 2371 , 2377 ,   // 44
    2381 , 2383 , 2389 , 2393 , 2399 , 2411 , 2417 , 2423 ,   // 45
    2437 , 2441 , 2447 , 2459 , 2467 , 2473 , 2477 , 2503 ,   // 46
    2521 , 2531 , 2539 , 2543 , 2549 , 2551 , 2557 , 2579 ,   // 47
    2591 , 2593 , 2609 , 2617 , 2621 , 2633 , 2647 , 2657 ,   // 48
    2659 , 2663 , 2671 , 2677 , 2683 , 2687 , 2689 , 2693 ,   // 49

    2699 , 2707 , 2711 , 2713 , 2719 , 2729 , 2731 , 2741 ,   // 50
    2749 , 2753 , 2767 , 2777 , 2789 , 2791 , 2797 , 2801 ,   // 51
    2803 , 2819 , 2833 , 2837 , 2843 , 2851 , 2857 , 2861 ,   // 52
    2879 , 2887 , 2897 , 2903 , 2909 , 2917 , 2927 , 2939 ,   // 53
    2953 , 2957 , 2963 , 2969 , 2971 , 2999 , 3001 , 3011 ,   // 54
    3019 , 3023 , 3037 , 3041 , 3049 , 3061 , 3067 , 3079 ,   // 55
    3083 , 3089 , 3109 , 3119 , 3121 , 3137 , 3163 , 3167 ,   // 56
    3169 , 3181 , 3187 , 3191 , 3203 , 3209 , 3217 , 3221 ,   // 57
    3229 , 3251 , 3253 , 3257 , 3259 , 3271 , 3299 , 3301 ,   // 58
    3307 , 3313 , 3319 , 3323 , 3329 , 3331 , 3343 , 3347 ,   // 59

    3359 , 3361 , 3371 , 3373 , 3389 , 3391 , 3407 , 3413 ,   // 60
    3433 , 3449 , 3457 , 3461 , 3463 , 3467 , 3469 , 3491 ,   // 61
    3499 , 3511 , 3517 , 3527 , 3529 , 3533 , 3539 , 3541 ,   // 62
    3547 , 3557 , 3559 , 3571 , 3581 , 3583 , 3593 , 3607 ,   // 63
    3613 , 3617 , 3623 , 3631 , 3637 , 3643 , 3659 , 3671 ,   // 64
    3673 , 3677 , 3691 , 3697 , 3701 , 3709 , 3719 , 3727 ,   // 65
    3733 , 3739 , 3761 , 3767 , 3769 , 3779 , 3793 , 3797 ,   // 66
    3803 , 3821 , 3823 , 3833 , 3847 , 3851 , 3853 , 3863 ,   // 67
    3877 , 3881 , 3889 , 3907 , 3911 , 3917 , 3919 , 3923 ,   // 68
    3929 , 3931 , 3943 , 3947 , 3967 , 3989 , 4001 , 4003 ,   // 69

    4007 , 4013 , 4019 , 4021 , 4027 , 4049 , 4051 , 4057 ,   // 70
    4073 , 4079 , 4091 , 4093 , 4099 , 4111 , 4127 , 4129 ,   // 71
    4133 , 4139 , 4153 , 4157 , 4159 , 4177 , 4201 , 4211 ,   // 72
    4217 , 4219 , 4229 , 4231 , 4241 , 4243 , 4253 , 4259 ,   // 73
    4261 , 4271 , 4273 , 4283 , 4289 , 4297 , 4327 , 4337 ,   // 74         
    4339 , 4349 , 4357 , 4363 , 4373 , 4391 , 4397 , 4409 ,   // 75
    4421 , 4423 , 4441 , 4447 , 4451 , 4457 , 4463 , 4481 ,   // 76
    4483 , 4493 , 4507 , 4513 , 4517 , 4519 , 4523 , 4547 ,   // 77
    4549 , 4561 , 4567 , 4583 , 4591 , 4597 , 4603 , 4621 ,   // 78
    4637 , 4639 , 4643 , 4649 , 4651 , 4657 , 4663 , 4673 ,   // 79

    4679 , 4691 , 4703 , 4721 , 4723 , 4729 , 4733 , 4751 ,   // 80
    4759 , 4783 , 4787 , 4789 , 4793 , 4799 , 4801 , 4813 ,   // 81
    4817 , 4831 , 4861 , 4871 , 4877 , 4889 , 4903 , 4909 ,   // 82
    4919 , 4931 , 4933 , 4937 , 4943 , 4951 , 4957 , 4967 ,   // 83
    4969 , 4973 , 4987 , 4993 , 4999 , 5003 , 5009 , 5011 ,   // 84
    5021 , 5023 , 5039 , 5051 , 5059 , 5077 , 5081 , 5087 ,   // 85
    5099 , 5101 , 5107 , 5113 , 5119 , 5147 , 5153 , 5167 ,   // 86
    5171 , 5179 , 5189 , 5197 , 5209 , 5227 , 5231 , 5233 ,   // 87
    5237 , 5261 , 5273 , 5279 , 5281 , 5297 , 5303 , 5309 ,   // 88
    5323 , 5333 , 5347 , 5351 , 5381 , 5387 , 5393 , 5399 ,   // 89

    5407 , 5413 , 5417 , 5419 , 5431 , 5437 , 5441 , 5443 ,   // 90
    5449 , 5471 , 5477 , 5479 , 5483 , 5501 , 5503 , 5507 ,   // 91
    5519 , 5521 , 5527 , 5531 , 5557 , 5563 , 5569 , 5573 ,   // 92
    5581 , 5591 , 5623 , 5639 , 5641 , 5647 , 5651 , 5653 ,   // 93
    5657 , 5659 , 5669 , 5683 , 5689 , 5693 , 5701 , 5711 ,   // 94
    5717 , 5737 , 5741 , 5743 , 5749 , 5779 , 5783 , 5791 ,   // 95
    5801 , 5807 , 5813 , 5821 , 5827 , 5839 , 5843 , 5849 ,   // 96
    5851 , 5857 , 5861 , 5867 , 5869 , 5879 , 5881 , 5897 ,   // 97
    5903 , 5923 , 5927 , 5939 , 5953 , 5981 , 5987 , 6007 ,   // 98
    6011 , 6029 , 6037 , 6043 , 6047 , 6053 , 6067 , 6073 ,   // 99

    6079 , 6089 , 6091 , 6101 , 6113 , 6121 , 6131 , 6133 ,   // 100
    6143 , 6151 , 6163 , 6173 , 6197 , 6199 , 6203 , 6211 ,   // 101
    6217 , 6221 , 6229 , 6247 , 6257 , 6263 , 6269 , 6271 ,   // 102
    6277 , 6287 , 6299 , 6301 , 6311 , 6317 , 6323 , 6329 ,   // 103
    6337 , 6343 , 6353 , 6359 , 6361 , 6367 , 6373 , 6379 ,   // 104
    6389 , 6397 , 6421 , 6427 , 6449 , 6451 , 6469 , 6473 ,   // 105
    6481 , 6491 , 6521 , 6529 , 6547 , 6551 , 6553 , 6563 ,   // 106
    6569 , 6571 , 6577 , 6581 , 6599 , 6607 , 6619 , 6637 ,   // 107
    6653 , 6659 , 6661 , 6673 , 6679 , 6689 , 6691 , 6701 ,   // 108
    6703 , 6709 , 6719 , 6733 , 6737 , 6761 , 6763 , 6779 ,   // 109

    6781 , 6791 , 6793 , 6803 , 6823 , 6827 , 6829 , 6833 ,   // 110
    6841 , 6857 , 6863 , 6869 , 6871 , 6883 , 6899 , 6907 ,   // 111
    6911 , 6917 , 6947 , 6949 , 6959 , 6961 , 6967 , 6971 ,   // 112
    6977 , 6983 , 6991 , 6997 , 7001 , 7013 , 7019 , 7027 ,   // 113
    7039 , 7043 , 7057 , 7069 , 7079 , 7103 , 7109 , 7121 ,   // 114
    7127 , 7129 , 7151 , 7159 , 7177 , 7187 , 7193 , 7207 ,   // 115
    7211 , 7213 , 7219 , 7229 , 7237 , 7243 , 7247 , 7253 ,   // 116
    7283 , 7297 , 7307 , 7309 , 7321 , 7331 , 7333 , 7349 ,   // 117
    7351 , 7369 , 7393 , 7411 , 7417 , 7433 , 7451 , 7457 ,   // 118
    7459 , 7477 , 7481 , 7487 , 7489 , 7499 , 7507 , 7517 ,   // 119

    7523 , 7529 , 7537 , 7541 , 7547 , 7549 , 7559 , 7561 ,   // 120
    7573 , 7577 , 7583 , 7589 , 7591 , 7603 , 7607 , 7621 ,   // 121
    7639 , 7643 , 7649 , 7669 , 7673 , 7681 , 7687 , 7691 ,   // 122
    7699 , 7703 , 7717 , 7723 , 7727 , 7741 , 7753 , 7757 ,   // 123
    7759 , 7789 , 7793 , 7817 , 7823 , 7829 , 7841 , 7853 ,   // 124
    7867 , 7873 , 7877 , 7879 , 7883 , 7901 , 7907 , 7919 ,   // 125
    7927 , 7933 , 7937 , 7949 , 7951 , 7963 , 7993 , 8009 ,   // 126
    8011 , 8017 , 8039 , 8053 , 8059 , 8069 , 8081 , 8087 ,   // 127
    8089 , 8093 , 8101 , 8111 , 8117 , 8123 , 8147 , 8161 ,   // 128
    8167 , 8171 , 8179 , 8191 , 8209 , 8219 , 8221 , 8231 ,   // 129

    8233 , 8237 , 8243 , 8263 , 8269 , 8273 , 8287 , 8291 ,   // 130
    8293 , 8297 , 8311 , 8317 , 8329 , 8353 , 8363 , 8369 ,   // 131
    8377 , 8387 , 8389 , 8419 , 8423 , 8429 , 8431 , 8443 ,   // 132
    8447 , 8461 , 8467 , 8501 , 8513 , 8521 , 8527 , 8537 ,   // 133
    8539 , 8543 , 8563 , 8573 , 8581 , 8597 , 8599 , 8609 ,   // 134
    8623 , 8627 , 8629 , 8641 , 8647 , 8663 , 8669 , 8677 ,   // 135
    8681 , 8689 , 8693 , 8699 , 8707 , 8713 , 8719 , 8731 ,   // 136
    8737 , 8741 , 8747 , 8753 , 8761 , 8779 , 8783 , 8803 ,   // 137
    8807 , 8819 , 8821 , 8831 , 8837 , 8839 , 8849 , 8861 ,   // 138
    8863 , 8867 , 8887 , 8893 , 8923 , 8929 , 8933 , 8941 ,   // 139

    8951 , 8963 , 8969 , 8971 , 8999 , 9001 , 9007 , 9011 ,   // 140
    9013 , 9029 , 9041 , 9043 , 9049 , 9059 , 9067 , 9091 ,   // 141
    9103 , 9109 , 9127 , 9133 , 9137 , 9151 , 9157 , 9161 ,   // 142
    9173 , 9181 , 9187 , 9199 , 9203 , 9209 , 9221 , 9227 ,   // 143
    9239 , 9241 , 9257 , 9277 , 9281 , 9283 , 9293 , 9311 ,   // 144
    9319 , 9323 , 9337 , 9341 , 9343 , 9349 , 9371 , 9377 ,   // 145
    9391 , 9397 , 9403 , 9413 , 9419 , 9421 , 9431 , 9433 ,   // 146
    9437 , 9439 , 9461 , 9463 , 9467 , 9473 , 9479 , 9491 ,   // 147
    9497 , 9511 , 9521 , 9533 , 9539 , 9547 , 9551 , 9587 ,   // 148
    9601 , 9613 , 9619 , 9623 , 9629 , 9631 , 9643 , 9649 ,   // 149

    9661 , 9677 , 9679 , 9689 , 9697 , 9719 , 9721 , 9733 ,   // 150
    9739 , 9743 , 9749 , 9767 , 9769 , 9781 , 9787 , 9791 ,   // 151
    9803 , 9811 , 9817 , 9829 , 9833 , 9839 , 9851 , 9857 ,   // 152
    9859 , 9871 , 9883 , 9887 , 9901 , 9907 , 9923 , 9929 ,   // 153
    9931 , 9941 , 9949 , 9967 , 9973 , 10007, 10009, 10037,   // 154
    10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099,   // 155
    10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163,   // 156
    10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247,   // 157
    10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303,   // 158
    10313, 10321, 10331, 10333, 10337, 10343, 10357, 10369,   // 159

    10391, 10399, 10427, 10429, 10433, 10453, 10457, 10459,   // 160
    10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531,   // 161
    10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627,   // 162
    10631, 10639, 10651, 10657, 10663, 10667, 10687, 10691,   // 163
    10709, 10711, 10723, 10729, 10733, 10739, 10753, 10771,   // 164
    10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859,   // 165
    10861, 10867, 10883, 10889, 10891, 10903, 10909, 10937,   // 166
    10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003,   // 167
    11027, 11047, 11057, 11059, 11069, 11071, 11083, 11087,   // 168
    11093, 11113, 11117, 11119, 11131, 11149, 11159, 11161,   // 169

    11171, 11173, 11177, 11197, 11213, 11239, 11243, 11251,   // 170
    11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317,   // 171
    11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399,   // 172
    11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483,   // 173
    11489, 11491, 11497, 11503, 11519, 11527, 11549, 11551,   // 174
    11579, 11587, 11593, 11597, 11617, 11621, 11633, 11657,   // 175
    11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731,   // 176
    11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813,   // 177
    11821, 11827, 11831, 11833, 11839, 11863, 11867, 11887,   // 178
    11897, 11903, 11909, 11923, 11927, 11933, 11939, 11941,   // 179

    11953, 11959, 11969, 11971, 11981, 11987, 12007, 12011,   // 180
    12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101,   // 181
    12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161,   // 182
    12163, 12197, 12203, 12211, 12227, 12239, 12241, 12251,   // 183
    12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323,   // 184
    12329, 12343, 12347, 12373, 12377, 12379, 12391, 12401,   // 185
    12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473,   // 186
    12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527,   // 187
    12539, 12541, 12547, 12553, 12569, 12577, 12583, 12589,   // 188
    12601, 12611, 12613, 12619, 12637, 12641, 12647, 12653,   // 189

    12659, 12671, 12689, 12697, 12703, 12713, 12721, 12739,   // 190
    12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821,   // 191
    12823, 12829, 12841, 12853, 12889, 12893, 12899, 12907,   // 192
    12911, 12917, 12919, 12923, 12941, 12953, 12959, 12967,   // 193
    12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033,   // 194
    13037, 13043, 13049, 13063, 13093, 13099, 13103, 13109,   // 195
    13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177,   // 196
    13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259,   // 197
    13267, 13291, 13297, 13309, 13313, 13327, 13331, 13337,   // 198
    13339, 13367, 13381, 13397, 13399, 13411, 13417, 13421,   // 199

    13441, 13451, 13457, 13463, 13469, 13477, 13487, 13499,   // 200
    13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597,   // 201
    13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681,   // 202
    13687, 13691, 13693, 13697, 13709, 13711, 13721, 13723,   // 203
    13729, 13751, 13757, 13759, 13763, 13781, 13789, 13799,   // 204
    13807, 13829, 13831, 13841, 13859, 13873, 13877, 13879,   // 205
    13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933,   // 206
    13963, 13967, 13997, 13999, 14009, 14011, 14029, 14033,   // 207
    14051, 14057, 14071, 14081, 14083, 14087, 14107, 14143,   // 208
    14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221,   // 209

    14243, 14249, 14251, 14281, 14293, 14303, 14321, 14323,   // 210
    14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407,   // 211
    14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461,   // 212
    14479, 14489, 14503, 14519, 14533, 14537, 14543, 14549,   // 213
    14551, 14557, 14561, 14563, 14591, 14593, 14621, 14627,   // 214
    14629, 14633, 14639, 14653, 14657, 14669, 14683, 14699,   // 215
    14713, 14717, 14723, 14731, 14737, 14741, 14747, 14753,   // 216
    14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821,   // 217
    14827, 14831, 14843, 14851, 14867, 14869, 14879, 14887,   // 218
    14891, 14897, 14923, 14929, 14939, 14947, 14951, 14957,   // 219

    14969, 14983, 15013, 15017, 15031, 15053, 15061, 15073,   // 220
    15077, 15083, 15091, 15101, 15107, 15121, 15131, 15137,   // 221
    15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217,   // 222
    15227, 15233, 15241, 15259, 15263, 15269, 15271, 15277,   // 223
    15287, 15289, 15299, 15307, 15313, 15319, 15329, 15331,   // 224
    15349, 15359, 15361, 15373, 15377, 15383, 15391, 15401,   // 225
    15413, 15427, 15439, 15443, 15451, 15461, 15467, 15473,   // 226
    15493, 15497, 15511, 15527, 15541, 15551, 15559, 15569,   // 227
    15581, 15583, 15601, 15607, 15619, 15629, 15641, 15643,   // 228
    15647, 15649, 15661, 15667, 15671, 15679, 15683, 15727,   // 229

    15731, 15733, 15737, 15739, 15749, 15761, 15767, 15773,   // 230
    15787, 15791, 15797, 15803, 15809, 15817, 15823, 15859,   // 231
    15877, 15881, 15887, 15889, 15901, 15907, 15913, 15919,   // 232
    15923, 15937, 15959, 15971, 15973, 15991, 16001, 16007,   // 233
    16033, 16057, 16061, 16063, 16067, 16069, 16073, 16087,   // 234
    16091, 16097, 16103, 16111, 16127, 16139, 16141, 16183,   // 235
    16187, 16189, 16193, 16217, 16223, 16229, 16231, 16249,   // 236
    16253, 16267, 16273, 16301, 16319, 16333, 16339, 16349,   // 237
    16361, 16363, 16369, 16381, 16411, 16417, 16421, 16427,   // 238
    16433, 16447, 16451, 16453, 16477, 16481, 16487, 16493,   // 239

    16519, 16529, 16547, 16553, 16561, 16567, 16573, 16603,   // 240
    16607, 16619, 16631, 16633, 16649, 16651, 16657, 16661,   // 241
    16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747,   // 242
    16759, 16763, 16787, 16811, 16823, 16829, 16831, 16843,   // 243
    16871, 16879, 16883, 16889, 16901, 16903, 16921, 16927,   // 244
    16931, 16937, 16943, 16963, 16979, 16981, 16987, 16993,   // 245
    17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053,   // 246
    17077, 17093, 17099, 17107, 17117, 17123, 17137, 17159,   // 247
    17167, 17183, 17189, 17191, 17203, 17207, 17209, 17231,   // 248
    17239, 17257, 17291, 17293, 17299, 17317, 17321, 17327,   // 249

    17333, 17341, 17351, 17359, 17377, 17383, 17387, 17389,   // 250
    17393, 17401, 17417, 17419, 17431, 17443, 17449, 17467,   // 251
    17471, 17477, 17483, 17489, 17491, 17497, 17509, 17519,   // 252
    17539, 17551, 17569, 17573, 17579, 17581, 17597, 17599,   // 253
    17609, 17623, 17627, 17657, 17659, 17669, 17681, 17683,   // 254
    17707, 17713, 17729, 17737, 17747, 17749, 17761, 17783,   // 255
    17789, 17791, 17807, 17827, 17837, 17839, 17851, 17863,   // 256
    17881, 17891, 17903, 17909, 17911, 17921, 17923, 17929,   // 257
    17939, 17957, 17959, 17971, 17977, 17981, 17987, 17989); // 258  < 18,000



{ == Local LbInteger routines ============================================= }
procedure LbBiInit(var N1 : LbInteger; Precision : Integer);
begin
  FillChar(N1, SizeOf(LbInteger), $00);

  if (Precision > 0) then
    N1.IntBuf.dwLen := Precision
  else
    N1.IntBuf.dwLen := cDEFAULT_PRECISION;

  N1.bSign := cDEFAULT_SIGN;
  N1.dwUsed := cDEFAULT_USED;

  N1.IntBuf.pBuf := pByte(AllocMem(N1.IntBuf.dwLen));
end;
{ ------------------------------------------------------------------- }
procedure LbBiRealloc(var N1 : LbInteger; Len : integer);                 {!!03}
var
  tmpPtr : pByte;
begin
  if (N1.dwUsed > Len) then
    Exit;
  tmpPtr := AllocMem(Len);
  move(N1.IntBuf.pBuf^, tmpPtr^, N1.dwUsed);
  FreeMem(N1.IntBuf.pBuf);
  N1.IntBuf.dwLen := Len;
  N1.IntBuf.pBuf := tmpPtr;
end;
{ ------------------------------------------------------------------- }
procedure LbBiFree(var N1 : LbInteger);
begin
  if (assigned(N1.IntBuf.pBuf)) then
    FreeMem(N1.IntBuf.pBuf);
  FillChar(N1, SizeOf(LbInteger), $00);
end;
{ ------------------------------------------------------------------- }
procedure LbBiClear(var N1 : LbInteger);
begin
  N1.bSign := cDEFAULT_SIGN;
  N1.dwUsed := cDEFAULT_USED;
  FillChar(N1.IntBuf.pBuf^, N1.IntBuf.dwLen, $00);
end;
{ ------------------------------------------------------------------- }
function LbBiGetByteValue (N1 : LbInteger; place : integer): byte;        {!!03}
begin
  if (N1.dwUsed < place) then begin
    Result := 0;
    exit;
  end;
  Result := pBiByteArray( N1.IntBuf.pBuf )[pred(place)];
end;
{ ------------------------------------------------------------------- }
procedure LbBiTrimSigZeros(var N1 : LbInteger);
begin
  if (not assigned(N1.IntBuf.pBuf)) then
    raise Exception.Create(sBIBufferNotAssigned);

  while(pBiByteArray( N1.IntBuf.pBuf )[pred(N1.dwUsed)] = 0)do begin
    dec(N1.dwUsed);
    { leave at least 1 zero }
    if (N1.dwUsed <= 0) then begin
      N1.dwUsed := 1;
      exit;
    end;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiVerify(var N1 : LbInteger);
begin
  { check to see that pointer points at data }
  if (not(assigned(N1.IntBuf.pBuf))) then
      raise Exception.Create(sBIBufferNotAssigned);

  { make sure that there are some numbers }
  if (N1.dwUsed = 0) then
      raise Exception.Create(sBINoNumber);

  LbBiTrimSigZeros(N1);  
end;
{ ------------------------------------------------------------------- }
procedure LbBiFindLargestUsed(N1 : LbInteger; N2 : LbInteger; var count : integer); {!!03}
begin
  if (N1.dwUsed >= N2.dwUsed) then
    Count := N1.dwUsed
  else
    Count := N2.dwUsed;
end;
{ ------------------------------------------------------------------- }
function LbBiFindFactor(B1 : byte) : byte;
begin
  Result := 1;
  while(B1 < $80)do begin
    B1 := (B1 shl 1);
    Result := Result * 2;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiPrepare(N1 : LbInteger; N2 : LbInteger;
                       var N3 : LbInteger);
begin
  { if pointer does not point at data then we make some }
  if (not(assigned(N3.IntBuf.pBuf))) then
    LbBiRealloc(N3, cDEFAULT_PRECISION);

  fillchar(N3.IntBuf.pBuf^, N3.IntBuf.dwLen, $00);
  N3.dwUsed := cDEFAULT_USED;
end;
{ ------------------------------------------------------------------- }
procedure LbBiCopy(var dest : LbInteger; src : LbInteger; len : Integer);
var
  ptr : pByte;
  size : integer;                                                         {!!03}
begin
  fillchar(dest.IntBuf.pBuf^, dest.IntBuf.dwLen, $00);

  size := integer(len);                                                   {!!03}

  if size > dest.IntBuf.dwLen then
    LbBiRealloc(dest, size);

  ptr := dest.IntBuf.pBuf;
  move(src.IntBuf.pBuf^, ptr^, len);

  if (dest.dwUsed < size) then
    dest.dwUsed := size;
end;
{ ------------------------------------------------------------------- }
function LbBiGetBit(N1 : LbInteger; bit : Integer) : Boolean;
var
  tmp : Integer;
  mask : byte;
begin
  mask := $01;
  mask := mask shl (bit mod 8);

  tmp := (bit div 8) + 1 ;
  tmp := LbBiGetByteValue(N1, tmp);

  Result := ((mask and tmp) = mask);

end;
{ ------------------------------------------------------------------- }
procedure LbBiAddByte(var N1 : LbInteger; place : integer; _byte : byte); {!!03}
begin
  if (place = cAPPEND_ARRAY) then begin
    if (succ(N1.dwUsed) > N1.IntBuf.dwLen) then
      LbBiRealloc(N1, succ(N1.dwUsed));
    pBiByteArray( N1.IntBuf.pBuf )[N1.dwUsed] := _byte;
    inc(N1.dwUsed);
  end else begin
    if (place > N1.IntBuf.dwLen) then
      LbBiRealloc(N1, place);
    pBiByteArray(N1.IntBuf.pBuf)[pred(place)] := _byte;
    if (N1.dwUsed < place) then
      N1.dwUsed := place;
  end;
end;
{ ------------------------------------------------------------------- }
function  LbBiCompare(N1 : LbInteger; N2 : LbInteger): Shortint;
var
  cnt : Integer;
begin
  LbBiTrimSigZeros( N1 );
  LbBiTrimSigZeros( N2 );
  if (N1.bSign <> N2.bSign) then begin
    if (N1.bSign = cPOSITIVE) then
      Result := cGREATER_THAN
    else
      Result := cLESS_THAN;
    exit;
  end;

  if (N1.dwUsed <> N2.dwUsed) then begin
    if (N1.dwUsed > N2.dwUsed) then begin
      Result := cGREATER_THAN;
      exit;
    end else begin
      Result := cLESS_THAN;
      exit;
    end;
  end;

  cnt := N1.dwUsed;
  while pBiByteArray( N1.IntBuf.pBuf )[pred(cnt)] =
        pBiByteArray( N2.IntBuf.pBuf )[pred(cnt)] do begin
    dec(cnt);
    if (cnt = 0) then begin
      Result := cEQUAL_TO;
      exit;
    end;
  end;

  if pBiByteArray( N1.IntBuf.pBuf )[pred(cnt)] >
     pBiByteArray( N2.IntBuf.pBuf )[pred(cnt)] then
    Result := cGREATER_THAN
  else
    Result := cLESS_THAN;
end;
{ ------------------------------------------------------------------- }
function  LbBiAbs(N1 : LbInteger; N2 : LbInteger): Shortint;
var
  cnt : Integer;
begin
  LbBiTrimSigZeros(N1);
  LbBiTrimSigZeros(N2);

  if (N1.dwUsed <> N2.dwUsed) then begin
    if (N1.dwUsed > N2.dwUsed) then begin
      Result := cGREATER_THAN;
      exit;
    end else begin
      Result := cLESS_THAN;
      exit;
    end;
  end;

  cnt := N1.dwUsed;
  while pBiByteArray( N1.IntBuf.pBuf )[pred(cnt)] =
        pBiByteArray( N2.IntBuf.pBuf )[pred(cnt)] do begin
    dec(cnt);
    if (cnt = 0) then begin
      Result := cEQUAL_TO;
      exit;
    end;
  end;

  if pBiByteArray( N1.IntBuf.pBuf )[pred(cnt)] >
     pBiByteArray( N2.IntBuf.pBuf )[pred(cnt)] then 
    Result := cGREATER_THAN
  else
    Result := cLESS_THAN;
end;
{ ------------------------------------------------------------------- }
function LbBiIsZero(N1 : LbInteger) : Boolean;
begin
  LbBiTrimSigZeros( N1 );
  Result := False;
  if (N1.dwUsed = 1) and (pBiByteArray( N1.IntBuf.pBuf )[0] = 0) then
    Result := True
end;
{ ------------------------------------------------------------------- }
function LbBiIsOne(N1 : LbInteger) : Boolean;
begin
  LbBiTrimSigZeros( N1 );
  Result := False;
  if (N1.dwUsed = 1) and (pBiByteArray( N1.IntBuf.pBuf )[0] = 1) then
    Result := True
end;
{ ------------------------------------------------------------------- }
function LbBiIsOdd(N1 : LbInteger): Boolean;
begin
  Result := odd(LbBiGetByteValue(N1, 1));
end;
{ ------------------------------------------------------------------- }
function LbBiIsEven(N1 : LbInteger): Boolean;
begin
  Result := not (odd(LbBiGetByteValue(N1, 1)));
end;
{ ------------------------------------------------------------------- }
procedure LbBiSwap(var N1 : LbInteger; var N2 : LbInteger);
var
  tmp : LbInteger;
begin
  tmp.bSign := N1.bSign;                                         {!!.01}
  tmp.dwUsed := N1.dwUsed;                                       {!!.01}
  tmp.IntBuf.dwLen := N1.IntBuf.dwLen;                           {!!.01}
  tmp.IntBuf.pBuf := N1.IntBuf.pBuf;                             {!!.01}

  N1.bSign := N2.bSign;                                          {!!.01}
  N1.dwUsed := N2.dwUsed;                                        {!!.01}
  N1.IntBuf.dwLen := N2.IntBuf.dwLen;                            {!!.01}
  N1.IntBuf.pBuf := N2.IntBuf.pBuf;                              {!!.01}

  N2.bSign := tmp.bSign;                                         {!!.01}
  N2.dwUsed := tmp.dwUsed;                                       {!!.01}
  N2.IntBuf.dwLen := tmp.IntBuf.dwLen;                           {!!.01}
  N2.IntBuf.pBuf := tmp.IntBuf.pBuf;                             {!!.01}
end;
{ ------------------------------------------------------------------- }
function LbBiReverseBits(byt : Byte) : Byte;
var
  i : byte;
  rBit : Byte;
begin
  Result := 0;
  rBit := $80;
  for i := 1 to 8 do begin
    if ((byt and $01) <> 0) then
      Result := Result or rBit;
    rBit := rBit shr 1;
    byt := byt shr 1;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiShr(var N1 : LbInteger; _shr : Integer);
var
  bitShr : byte;
  byteShr : Integer;
  carry : byte;
  tmp : word;
  shifted : byte;
  i : Integer;
  t : LbInteger;
begin
  if _shr < 1 then exit;                       {!!.01}

  LbBiVerify(N1);
  LbBiInit(t, cDEFAULT_PRECISION);
  LbBiAddByte(t, cPREPEND_ARRAY, $00);

  byteShr := _shr div 8;       
  bitShr := _shr mod 8;
  if( byteShr > integer( N1.dwUsed ))then begin
    LbBiClear( N1 );
    LbBiAddByte( N1, cPREPEND_ARRAY, $00 );
  end;

  carry := 0;
  try
    for i := N1.dwUsed downto 1 do begin
      if (i - byteShr) < 1 then break;
      tmp := pBiByteArray( N1.IntBuf.pBuf )[pred(i)];
      shifted := (tmp shr bitShr) or carry;
      LbBiAddByte(t, i - byteShr, byte(shifted and $00FF));
      carry := ((tmp shl (8 - bitShr)) and $00FF);
    end;
    LbBiCopy(N1, t, t.dwUsed);
  finally
    LbBiTrimSigZeros( N1 );
    LbBiFree(t);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiShl(var N1 : LbInteger; _shl : Integer);
var
  bitShl : byte;
  byteShl : Integer;
  tmp : word;
  shifted : byte;
  carry : byte;
  t : LbInteger;
  i : Integer;
  x : Integer;
begin

  if _shl < 1 then exit;                       {!!.01}
  LbBiVerify(N1);
  LbBiInit(t, cDEFAULT_PRECISION);
  LbBiAddByte(t, cPREPEND_ARRAY, $00);

  byteShl := _shl div 8;
  bitShl := _shl mod 8;

  try
    carry := 0;
    x := 0;
    for i := 1 to N1.dwUsed do begin
      tmp := pBiByteArray( N1.IntBuf.pBuf )[pred(i)];
      shifted := ((tmp shl bitShl) and $00FF) or carry;
      LbBiAddByte(t, i + byteShl, byte(shifted and $00FF));
      carry := ((tmp shr (8 - bitShl)) and $00FF);
      x := i;
    end;
    LbBiAddByte(t, succ(x) + byteShl, carry);
    LbBiCopy(N1, t, t.dwUsed);
  finally
    LbBiTrimSigZeros(N1);
    LbBiFree(t);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiOR(N1 : LbInteger; N2 : LbInteger; var NOR : LbInteger);
var
  count : integer;                                                        {!!03}
  i : integer;                                                            {!!03}
  a : byte;
  b : byte;
begin
  LbBiVerify(N1);
  LbBiVerify(N2);
  LbBiPrepare(N1, N2, NOR);

  LbBiAddByte(NOR, cPREPEND_ARRAY, $00);
  LbBiFindLargestUsed(N1, N2, count);
  for i := 1 to count do begin
    a := LbBiGetByteValue(N1, i);
    b := LbBiGetByteValue(N2, i);
    a := a or b;
    LbBiAddByte(NOR, i, a);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiORInPlace(var N1 : LbInteger; N2 : LbInteger);
var
  Nor : LbInteger;
  prec : Integer;
begin
  if (N1.dwUsed > N2.dwUsed) then prec := succ(N1.dwUsed)
  else                            prec := succ(N2.dwUsed);
  LbBiInit(Nor, prec);
  try
    LbBiOR(N1, N2, Nor);
    LbBiClear(N1);
    N1.dwUsed := Nor.dwUsed;
    N1.bSign := Nor.bSign;
    if (N1.IntBuf.dwLen < Nor.IntBuf.dwLen) then
      LbBiRealloc(N1, Nor.IntBuf.dwLen);
    LbBiCopy(N1 , Nor, Nor.dwUsed);
  finally
    LbBiFree(Nor);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiXOR(N1 : LbInteger; N2 : LbInteger; var NXOR : LbInteger);
var
  count : integer;                                                        {!!03}
  i : integer;                                                            {!!03}
  a : byte;
  b : byte;
begin
  LbBiVerify(N1);
  LbBiVerify(N2);
  LbBiPrepare(N1, N2, NXOR);

  LbBiAddByte(NXOR, cPREPEND_ARRAY, $00);
  LbBiFindLargestUsed(N1, N2, count);
  for i := 1 to count do begin
    a := LbBiGetByteValue(N1, i);
    b := LbBiGetByteValue(N2, i);
    a := a xor b;
    LbBiAddByte(NXOR, i, a);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiXORInPlace(var N1 : LbInteger; N2 : LbInteger);
var
  Nxor : LbInteger;
  prec : Integer;
begin
  if (N1.dwUsed > N2.dwUsed) then prec := succ(N1.dwUsed)
  else                            prec := succ(N2.dwUsed);
  LbBiInit(Nxor, prec);
  try
    LbBiXOR(N1, N2, Nxor);
    LbBiClear(N1);
    N1.dwUsed := Nxor.dwUsed;
    N1.bSign := Nxor.bSign;
    if (N1.IntBuf.dwLen < Nxor.IntBuf.dwLen) then
      LbBiRealloc(N1, Nxor.IntBuf.dwLen);
    LbBiCopy(N1 , Nxor, Nxor.dwUsed);
  finally
    LbBiFree(Nxor);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiMove(var dest : LbInteger; src : LbInteger;
                    place : integer; len : Integer);                      {!!03}
var
  ptr : pByte;
  size : integer;                                                         {!!03}
begin
  if (not assigned(dest.IntBuf.pBuf)) then
    raise Exception.Create(sBIBufferNotAssigned);

  if (place = cAPPEND_ARRAY) then begin
    if ((integer(len) + dest.dwUsed) > dest.IntBuf.dwLen) then            {!!03}
      LbBiRealloc(dest, (integer(len) + dest.dwUsed));                    {!!03}

    ptr := dest.IntBuf.pBuf;
    inc(ptr, dest.dwUsed);
    move(src.IntBuf.pBuf^, ptr^, len);
    inc(dest.dwUsed, len);
  end else begin
    size := pred(place) + integer(len);                                   {!!03}
    if size > dest.IntBuf.dwLen then
      LbBiRealloc(dest, size);
    ptr := dest.IntBuf.pBuf;
    inc(ptr, pred(place));
    move(src.IntBuf.pBuf^, ptr^, len);
    if (dest.dwUsed < size) then
      dest.dwUsed := size;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddBase(N1 : LbInteger; N2 : LbInteger; var Sum : LbInteger);
var
  Carry : byte;
  cnt : Integer;
  Count : integer;                                                        {!!03}
  tmp_wrd : WORD;
  tmp_byt : byte;
begin
  LbBiFindLargestUsed(N1, N2, Count);

  if( LbBiIsZero( N1 ))then begin
    LbBiCopy(sum, N2, N2.dwUsed);
    exit;
  end;

  if( LbBiIsZero( N2 ))then begin
    LbBiCopy(sum, N1, N1.dwUsed);
    exit;
  end;

  Carry := 0;
  if (succ(count) > Sum.dwUsed) then
    LbBiRealloc(Sum, succ(count));
  { add digits }
  for cnt := 1 to count do begin
    tmp_wrd := LbBiGetByteValue(N1, cnt) +
               LbBiGetByteValue(N2, cnt) + Carry;
    tmp_byt := tmp_wrd and $00FF;
    Carry   := tmp_wrd shr 8;
    pBiByteArray(Sum.IntBuf.pBuf )[Sum.dwUsed] := tmp_byt;
    inc(Sum.dwUsed);
  end;
  { finish by adding the carry }
  LbBiAddByte(Sum, cAPPEND_ARRAY, Carry);
  { trim off any significant zeros }
  LbBiTrimSigZeros(Sum);
end;
{ ------------------------------------------------------------------- }
procedure LbBiSubBase(N1 : LbInteger; N2 : LbInteger;
                       var Diff : LbInteger);
var
  tmp : integer;
  Borrow : WORD;
  cnt : integer;                                                          {!!03}
  x : integer;                                                            {!!03}
begin
  if( LbBiIsZero( N1 ))then begin
    LbBiCopy(Diff, N2, N2.dwUsed);
    exit;
  end;

  if( LbBiIsZero( N2 ))then begin
    LbBiCopy(Diff, N1, N1.dwUsed);
    exit;
  end;

  Borrow := 0;
  x := pred(N1.dwUsed);
  for cnt := 0 to x do begin
    tmp := pBiByteArray(N1.IntBuf.pBuf)[cnt];
    if (N2.dwUsed < succ(cnt)) then
      tmp := tmp - Borrow
    else
      tmp := tmp - (pBiByteArray(N2.IntBuf.pBuf)[cnt] + Borrow);

    if (tmp < 0) then begin
      inc(tmp, cBYTE_POSSIBLE_VALUES);
      Borrow := 1;
    end else
      Borrow := 0;

    if (succ(Diff.dwUsed) > Diff.IntBuf.dwLen) then
      LbBiRealloc(Diff, succ(Diff.dwUsed));
    pBiByteArray(Diff.IntBuf.pBuf )[Diff.dwUsed] := tmp;
    inc(Diff.dwUsed);
  end;
  if (Borrow <> 0) then
    raise Exception.Create(sBISubtractErr);
  { trim off any significant zeros }
  LbBiTrimSigZeros(Diff);
end;
{ ------------------------------------------------------------------- }
procedure LbBiAdd(N1 : LbInteger; N2 : LbInteger; var Sum : LbInteger);
var
  value : Shortint;
begin
  if (N1.bSign = N2.bSign) then begin
    Sum.bSign := N1.bSign;
    LbBiAddBase(N1, N2, Sum);
  end else begin
    value := LbBiAbs(N1, N2);
    if (value = cEQUAL_TO) then begin
      LbBiAddByte(Sum, cPREPEND_ARRAY, $00);
      exit;
    end else if (value = cGREATER_THAN) then begin
      Sum.bSign := N1.bSign;
      LbBiSubBase(N1, N2, Sum);
    end else begin
      Sum.bSign := N2.bSign;
      LbBiSubBase(N2, N1, Sum);
    end;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiSub(N1 : LbInteger; N2 : LbInteger; var diff : LbInteger);
begin
  N2.bSign := not N2.bSign;
  LbBiAdd(N1, N2, diff);
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddInPlace(var N1 : LbInteger; N2 : LbInteger);
var
  sum : LbInteger;
  prec : Integer;
begin
  if (N1.dwUsed > N2.dwUsed) then
    prec := succ(N1.dwUsed)
  else
    prec := succ(N2.dwUsed);

  LbBiInit(sum, prec);
  try
    LbBiAdd(N1, N2, sum);
    LbBiClear(N1);
    N1.dwUsed := sum.dwUsed;
    N1.bSign := sum.bSign;
    if (N1.IntBuf.dwLen < sum.IntBuf.dwLen) then
      LbBiRealloc(N1, sum.IntBuf.dwLen);

    LbBiCopy(N1 , sum, sum.dwUsed);
  finally
    LbBiFree(sum);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiSubInPlace(var N1 : LbInteger;  N2 : LbInteger);
var
  Difference : LbInteger;
  prec : Integer;
begin
  if (N1.dwUsed > N2.dwUsed) then
    prec := succ(N1.dwUsed)
  else
    prec := succ(N2.dwUsed);

  LbBiInit(Difference, prec);
  try
    LbBiSub(N1, N2, Difference);
    LbBiClear(N1);
    N1.dwUsed := Difference.dwUsed;
    N1.bSign := Difference.bSign;
    if (N1.IntBuf.dwLen < Difference.IntBuf.dwLen) then
      LbBiRealloc(N1, Difference.IntBuf.dwLen);

    LbBiCopy(N1, Difference, Difference.dwUsed);
  finally
    LbBiFree(Difference);
  end;
end;
{ ------------------------------------------------------------------- }
function MultSpecialCase(N1 : LbInteger; N2 : LbInteger;
                        var Product : LbInteger) : Boolean;
begin
  Result := False;
  { if either one is zero then the product is zero }
  if (LbBiIsZero(N1) or LbBiIsZero(N2)) then begin
    LbBiAddByte(Product, cPREPEND_ARRAY, $00);
    Result := True;
    exit;
  end;

  { if N1 := 1 }
  if (LbBiIsOne(N1)) then begin
    product.dwUsed := N2.dwUsed;

    if (product.IntBuf.dwLen < N2.IntBuf.dwLen) then
      LbBiRealloc(product, N2.IntBuf.dwLen);

    LbBiCopy(product, N2, N2.dwUsed);
    Result := True;
    exit;
  end;

  { if N2 := 1 }
  if (LbBiIsOne(N2)) then begin
    product.dwUsed := N1.dwUsed;

    if (product.IntBuf.dwLen < N1.IntBuf.dwLen) then
      LbBiRealloc(product, N1.IntBuf.dwLen);

    LbBiCopy(product, N1, N1.dwUsed);
    Result := True;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiMultBase(N1 : LbInteger; N2 : LbInteger;
                        var Product : LbInteger);
var
  InxX : integer;                                                         {!!03}
  InxY : integer;                                                         {!!03}
  MaxX : integer;                                                         {!!03}
  Carry : integer;                                                        {!!03}
  prd : integer;                                                          {!!03}
  plc : integer;                                                          {!!03}
  byt : byte;
  tmp : integer;                                                          {!!03}
begin
  if (MultSpecialCase(N1, N2, Product)) then
    exit;
  MaxX := pred(N1.dwUsed);
  tmp := pred(N2.dwUsed);
  for InxY := 0 to tmp do begin
    if pBiByteArray(N2.IntBuf.pBuf)[InxY] <> 0 then begin
      Carry := 0;
      for InxX := 0 to MaxX do begin
        plc := InxX + InxY;
        prd := pBiByteArray(N1.IntBuf.pBuf)[InxX];
        prd := prd * pBiByteArray(N2.IntBuf.pBuf)[InxY];
        if (Product.dwUsed < plc) then
          prd := prd + Carry
        else
          prd := prd + pBiByteArray(Product.IntBuf.pBuf)[plc] + Carry;

        byt := prd and $00FF;
        Carry := prd shr 8;

        if (succ(plc) > Product.IntBuf.dwLen) then
          LbBiRealloc(Product, plc + 100);
        pBiByteArray(Product.IntBuf.pBuf )[plc] := byt;
        if (Product.dwUsed < succ(plc)) then
          N1.dwUsed := succ(plc);
      end;
      LbBiAddByte(Product, (MaxX + InxY + 2), Carry);
    end;
   end;
  { trim off any significant zeros }
  LbBiTrimSigZeros(Product);
end;
{ ------------------------------------------------------------------- }
procedure LbBiMult(N1 : LbInteger; N2 : LbInteger;
                    var Product : LbInteger);
begin
  LbBiMultBase(N1, N2, Product);
  if (N1.bSign = N2.bSign) then
    Product.bSign := cPOSITIVE
  else
    Product.bSign := cNEGATIVE;
end;
{ ------------------------------------------------------------------- }
procedure LbBiMultInPlace(var N1 : LbInteger; N2 : LbInteger);
var
  product : LbInteger;
  precis : Integer;
begin
  precis := (N1.dwUsed + N2.dwUsed) * 2;
  LbBiInit(product, precis);
  LbBiMult(N1, N2, product);
  LbBiClear(N1);
  N1.dwUsed := product.dwUsed;
  N1.bSign := product.bSign;
  if (N1.IntBuf.dwLen < product.IntBuf.dwLen) then
    LbBiRealloc(N1, product.IntBuf.dwLen);
  LbBiCopy(N1, product, product.dwUsed);
  LbBiFree(product);
end;
{ ------------------------------------------------------------------- }
procedure LbBiMulByDigitBase(N1 : LbInteger; N2 : byte;
                             var product : LbInteger);
var
  cnt : integer;                                                          {!!03}
  carry : byte;
  prd : WORD;
  byt : byte;
  tmp : integer;                                                          {!!03}
begin                                                                     
  if (N2 = 1) then begin
    if (product.IntBuf.dwLen < N1.IntBuf.dwLen) then
      LbBiRealloc(product, N1.IntBuf.dwLen);
    product.dwUsed := N1.dwUsed;
    product.bSign := N1.bSign;
    LbBiCopy(product, N1, N1.dwUsed);
  end;

  if (n2 = 0) then begin
    product.dwUsed := 1;
    LbBiAddByte(product, cPREPEND_ARRAY, 0);
  end;

  if LbBiIsOne( N1 ) then begin
    product.dwUsed := 1;
    LbBiAddByte(product, cPREPEND_ARRAY, N2);
  end;
  { we can do this here since LbBiIsOne() did the clean up on N1 }
  if (N1.dwUsed = 1) and (pBiByteArray( N1.IntBuf.pBuf )[0] = 0) then begin {!!.01}
    product.dwUsed := 1;
    LbBiAddByte(product, cPREPEND_ARRAY, 0);
  end;

  Carry := 0;
  tmp := pred( N1.dwUsed );
  for cnt := 0 to tmp do begin
    prd   := (pBiByteArray( N1.IntBuf.pBuf )[cnt] * N2) + Carry;
    byt   := prd and $00FF;
    Carry := prd shr 8;
    pBiByteArray(Product.IntBuf.pBuf )[cnt] := byt;
    if (Product.dwUsed < succ(cnt)) then
      N1.dwUsed := succ(cnt);
  end;
  LbBiAddByte(Product, succ(N1.dwUsed), Carry);
  LbBiTrimSigZeros(Product);
end;
{ ------------------------------------------------------------------- }
procedure LbBiMulByDigit(N1 : LbInteger; N2 : byte;
                          var product : LbInteger);
begin
  LbBiMulByDigitBase(N1, N2, product);
  product.bSign := N1.bSign;
end;
{ ------------------------------------------------------------------- }
procedure LbBiMulByDigitInPlace(var N1 : LbInteger; N2 : byte);
var
 product : LbInteger;
 precis : Integer;
begin
  precis := (N1.dwUsed + 1) * 2;
  LbBiInit(product, precis);
  try
    LbBiMulByDigit(N1, N2, product);
    if (N1.IntBuf.dwLen < product.IntBuf.dwLen) then
      LbBiRealloc(N1, product.IntBuf.dwLen);
    N1.bSign := product.bSign;
    N1.dwUsed := product.dwUsed;
    LbBiCopy(N1, product, product.dwUsed);
  finally
    LbBiFree(product);

  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiDivByDigitBase(N1 : LbInteger; N2 : byte;
                              var quotient : LbInteger;
                              var remainder : byte);
var
  factor : byte;
  c : Integer;
  tmp : Integer;
  sigDivd : longint;
  lclQT : longint;
  Carry : WORD;
  plc : integer;                                                          {!!03}  
  lclDVD : LbInteger;
  divisor : byte;
begin
  LbBiInit(lclDVD, N1.dwUsed);
  Carry := 0;
  try
    if (LbBiIsZero(N1)) then begin
        LbBiAddByte(quotient, cPREPEND_ARRAY, $00);
        exit;
      end;
    if (N2 = 1) then begin
      LbBiCopy(quotient, N1, N1.dwUsed);
      exit;
    end;
    if (N2 = 0) then
      raise Exception.Create(sBIZeroDivide);

    LbBiCopy(lclDVD, N1, N1.dwUsed);
    divisor := N2;

    { Find the factor to increase the Significant byte greater than $80 }
    factor := LbBiFindFactor(N2);
    if (factor <> 1) then begin
      LbBiMulByDigitInPlace(lclDVD, factor);
      divisor := divisor * factor;
    end;


    if pBiByteArray( lclDVD.IntBuf.pBuf )[pred(lclDVD.dwUsed)] >= divisor then begin
      LbBiAddByte(lclDVD, cAPPEND_ARRAY, $00);
    end;

    LbBiClear(quotient);
    remainder := 0;

    plc := pred(lclDVD.dwUsed);
    if (lclDVD.dwUsed > quotient.dwUsed) then
       LbBiRealloc(quotient, lclDVD.dwUsed);
    Carry := 0;
    tmp := pred(lclDVD.dwUsed);
    for c := tmp downto 0 do begin
      sigDivd := (Carry shl 8) or (integer(pBiByteArray(lclDVD.IntBuf.pBuf)[c])); {!!03}
      if (SigDivd < divisor) then begin
        Carry := SigDivd;
        dec(plc);
        continue;
      end;

      lclQT := sigDivd div divisor;
      if (lclQT <> 0) then begin
        if (lclQT >= cBYTE_POSSIBLE_VALUES) then
          lclQT := pred(cBYTE_POSSIBLE_VALUES);

        while sigDivd < (divisor * lclQT)do begin
          dec(lclQT);
          if (lclQT = 0) then
            raise Exception.Create(sBIQuotientErr);
        end;
      end;

      if (lclQT <> 0) then begin
        pBiByteArray(quotient.IntBuf.pBuf )[plc] := lclQT;
        if (quotient.dwUsed < succ(plc)) then
          quotient.dwUsed := succ(plc);

        Carry := sigDivd - (divisor * lclQT);
      end;
      dec(plc);
    end;
  finally
    remainder := Carry;
    if (quotient.dwUsed = 0) then
      LbBiAddByte(quotient, cPREPEND_ARRAY, $00);

    LbBiFree(lclDVD);
    LbBiTrimSigZeros(quotient);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiDivByDigit(N1 : LbInteger; N2 : byte;
                          var quotient : LbInteger;
                          var remainder : byte);
begin
  LbBiDivByDigitBase(N1, N2, quotient, remainder);
  quotient.bSign := N1.bSign;
end;
{ ------------------------------------------------------------------- }
procedure LbBiDivByDigitInPlace(var N1 : LbInteger;
                                      N2 : byte;
                                  var remainder : byte);
var
  tmp : LbInteger;
  precis : Integer;
begin
  precis := (N1.dwUsed + 1) * 2;
  LbBiInit(tmp, precis);
  try
    LbBiDivByDigit(N1, N2, tmp, remainder);

    N1.dwUsed := tmp.dwUsed;
    N1.bSign := tmp.bSign;
    if (N1.IntBuf.dwLen < tmp.IntBuf.dwLen) then
      LbBiRealloc(N1, tmp.IntBuf.dwLen);
    LbBiCopy(N1, tmp, tmp.dwUsed);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiDivBase(N1 : LbInteger; N2 : LbInteger;
                       var quotient : LbInteger;
                       var remainder : LbInteger);
var
  factor : byte;
  InxQ : Integer;
  InxX : Integer;
  tmpByte : byte;
  tmpInt : integer;
  sigDigit : byte;
  lclQT : longint;
  lclDVD : LbInteger;
  lclDSR : LbInteger;
  tmpDR : LbInteger;
  tmpBN : LbInteger;
  sigDivd : longint;
begin
  LbBiInit(lclDVD, N1.dwUsed);
  LbBiInit(lclDSR, N1.dwUsed);
  LbBiInit(tmpDR, N1.dwUsed);
  LbBiInit(tmpBN, N1.dwUsed);
  try
    { Should move special cases to a seperate procedure }
    if (N1.dwUsed < 1)or
      (N2.dwUsed < 1) then
        raise Exception.Create(sBINoNumber);

    if LbBiIsZero( N1 )then begin
      LbBiAddByte(quotient , cPREPEND_ARRAY, $00);
      LbBiAddByte(remainder, cPREPEND_ARRAY, $00);
      exit;
    end;

    if LbBiIsOne( N2 )then begin
      LbBiCopy(quotient, N1, N1.dwUsed);
      LbBiAddByte(remainder, cPREPEND_ARRAY, $00);
      exit;
    end;
    if LbBiIsZero( N2 )then  
        raise Exception.Create(sBIZeroDivide);


    { since only the pointer is saved and not the memory pointed at we }
    { need to move it over to preserve the numbers                     }
    LbBiCopy(lclDVD, N1, N1.dwUsed);
    LbBiCopy(lclDSR, N2, N2.dwUsed);

    { Find the factor to increase the Significant byte greater than $80 }
    LbBiTrimSigZeros(lclDSR);

    tmpByte := pBiByteArray(lclDSR.IntBuf.pBuf)[pred(lclDSR.dwUsed)];
    if (tmpByte = 0) then
      raise Exception.Create(sBIZeroFactor);

    factor := LbBiFindFactor(tmpByte);
    if (factor <> 1) then begin
      LbBiMulByDigitInPlace(lclDVD, factor);
      LbBiMulByDigitInPlace(lclDSR, factor);
    end;

    {***************************************************************************
    {* if the most sigDigit of the dividend is greater than or
    {* equal to that of the divisor, increment the number of
    {*  digits in the dividend;
    {**************************************************************************}
    if pBiByteArray(lclDVD.IntBuf.pBuf)[pred(lclDVD.dwUsed)] >=
       pBiByteArray(lclDSR.IntBuf.pBuf)[pred(lclDSR.dwUsed)] then begin
      LbBiAddByte(lclDVD, cAPPEND_ARRAY, $00);
    end;

    while(lclDVD.dwUsed < lclDSR.dwUsed)do
      LbBiAddByte(lclDVD, cAPPEND_ARRAY, $00);

    InxQ := lclDVD.dwUsed - lclDSR.dwUsed + 1;
    InxX := lclDVD.dwUsed;

    LbBiClear(quotient);
    LbBiClear(remainder);

    sigDigit := pBiByteArray(lclDSR.IntBuf.pBuf)[pred(lclDSR.dwUsed)];
    if (sigDigit = 0) then begin
      tmpInt := pred(lclDSR.dwUsed);
      while sigDigit = 0 do begin
        sigDigit := pBiByteArray(lclDSR.IntBuf.pBuf)[tmpInt];
        dec(tmpInt);
        if tmpInt < 0 then
          raise Exception.Create(sBIQuotientErr);
      end;
    end;

    while InxQ >= 1 do begin
      if (lclDVD.dwUsed = 1) then
        sigDivd := pBiByteArray(lclDVD.IntBuf.pBuf)[0]
      else
        sigDivd := integer(pBiByteArray(lclDVD.IntBuf.pBuf)[InxX])        {!!03}
                   shl 8 + pBiByteArray(lclDVD.IntBuf.pBuf)[pred(InxX)];

      lclQT := sigDivd div sigDigit;
      if (lclQT <> 0) then begin
        if (lclQT >= cBYTE_POSSIBLE_VALUES) then
          lclQT := pred(cBYTE_POSSIBLE_VALUES);

        LbBiClear(tmpDR);
        LbBiMove(tmpDR, lclDSR, InxQ, lclDSR.dwUsed);

        LbBiMulByDigitInPlace(tmpDR, lclQT);

        while(LbBiCompare(lclDVD, tmpDR) = cLESS_THAN)do begin
          dec(lclQT);
          if (lclQT = 0) then break;

          LbBiClear(tmpDR);
          LbBiMove(tmpDR, lclDSR, InxQ, lclDSR.dwUsed);

          LbBiMulByDigitInPlace(tmpDR, lclQT);
        end;
      end;

      if (lclQT <> 0) then begin

        LbBiAddByte(quotient, InxQ , lclQT);
        LbBiSubInPlace (lclDVD, tmpDR);
      end;
      dec(InxX);
      dec(InxQ);
    end;

    LbBiCopy(remainder, lclDVD, lclDVD.dwUsed);

    if (factor <> 0) then begin
      if (remainder.dwUsed > 1) then begin
        LbBiDivByDigitInPlace(remainder, factor, tmpByte);
      end else if (remainder.dwUsed = 1) then begin
        tmpByte := pBiByteArray(remainder.IntBuf.pBuf)[0];
        tmpByte := tmpByte div factor;
        LbBiAddByte(remainder, cPREPEND_ARRAY, tmpByte);
      end;
    end;
  finally
    LbBiFree(lclDVD);
    LbBiFree(lclDSR);
    LbBiFree(tmpDR);
    LbBiFree(tmpBN);

    if (quotient.dwUsed = 0) then
      LbBiAddByte(quotient, cPREPEND_ARRAY, $00);

    if (remainder.dwUsed = 0) then begin
      LbBiAddByte(remainder, cPREPEND_ARRAY, $00);
    end;

    LbBiTrimSigZeros(quotient);
    LbBiTrimSigZeros(remainder);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiDiv(N1 : LbInteger; N2 : LbInteger;
                   var quotient : LbInteger;
                   var remainder : LbInteger);
begin
  LbBiDivBase(N1, N2, quotient, remainder);
  if (N1.bSign = N2.bSign) then
    quotient.bSign := cPOSITIVE
  else
    quotient.bSign := cNEGATIVE;
end;
{ ------------------------------------------------------------------- }
procedure LbBiDivInPlace(var N1 : LbInteger;
                              N2 : LbInteger;
                          var remainder : LbInteger);
var
  quotient : LbInteger;
begin
  LbBiInit(quotient, N1.dwUsed);
  try
    LbBiDiv(N1, N2, quotient, remainder);
    LbBiClear(N1);
    N1.dwUsed := quotient.dwUsed;
    N1.bSign := quotient.bSign;
    if (N1.IntBuf.dwLen < quotient.IntBuf.dwLen) then
      LbBiRealloc(N1, quotient.IntBuf.dwLen);
    LbBiCopy(N1, quotient, quotient.dwUsed);
  finally
    LbBiFree(quotient);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiMod(N1 : LbInteger; N2 : LbInteger; var remainder : LbInteger);
var
  quotient : LbInteger;
begin
  LbBiInit(quotient, N2.dwUsed);
  LbBiDiv(N1, N2, quotient, remainder);
  LbBiFree(quotient);
end;
{ ------------------------------------------------------------------- }
procedure LbBiModInPlace(var N1 : LbInteger; Modulas : LbInteger);
var
  remainder : LbInteger;
begin
  LbBiInit(remainder, Modulas.dwUsed);
  LbBiMod(N1, Modulas, remainder);

  LbBiClear(N1);
  N1.dwUsed := remainder.dwUsed;
  N1.bSign := remainder.bSign;

  if (N1.IntBuf.dwLen < remainder.IntBuf.dwLen) then
    LbBiRealloc(N1, remainder.IntBuf.dwLen);

  LbBiCopy(N1, remainder, remainder.dwUsed);
  LbBiFree(remainder);
end;
{ ------------------------------------------------------------------- }
procedure LbBiPowerAndMod(I1 : LbInteger;
                           exponent : LbInteger;
                           modulus : LbInteger;
                           var _Result : LbInteger);
var
  BitCount : Integer;
  i : Integer;
  tmp_byte : byte;
  hold : LbInteger;
begin
  LbBiClear(_Result);

  if (LbBiIsZero(exponent)) then begin
    LbBiAddByte(_Result , cPREPEND_ARRAY, $01);
    exit;
  end;
  LbBiInit (hold, cDEFAULT_PRECISION);
  try
    i := exponent.dwUsed;
    LbBiAddByte(_Result , cPREPEND_ARRAY, $01);
    while i > 0 do begin
      tmp_byte := LbBiGetByteValue(exponent, i);
      dec(i);
      Bitcount := 8;
      tmp_byte := LbBiReverseBits(tmp_byte);

      while bitcount > 0 do begin
        {r = r^2 mod m }
        LbBiMultInPlace(_Result, _Result);
        LbBiModInPlace(_Result, modulus);
        if Odd(tmp_byte) then begin
          { r = (r * n) mod m }
          LbBiMultInPlace(_Result, I1);
          LbBiModInPlace(_Result, modulus);
        end;
        tmp_byte := tmp_byte shr 1;
        dec(Bitcount);
      end;
    end;
  finally
    LbBiFree(hold);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiPowerAndModInPLace(var I1 : LbInteger;
                                  exponent : LbInteger;
                                  modulus : LbInteger);
var
  _Result : LbInteger;
begin
  LbBiInit(_Result, cUSE_DEFAULT_PRECISION);
  try
    LbBiPowerAndMod(I1, exponent, modulus, _Result);
    LbBiClear(I1);
    I1.dwUsed := _Result.dwUsed;
    I1.bSign := _Result.bSign;
    if (I1.IntBuf.dwLen < _Result.IntBuf.dwLen) then
      LbBiRealloc(I1, _Result.IntBuf.dwLen);
    LbBiCopy(I1, _Result, _Result.dwUsed);
  finally
    LbBiFree(_Result);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddByDigit(N1 : LbInteger; N2 : byte; var Sum : LbInteger);
var
  tmp : LbInteger;
begin
  LbBiInit(tmp, N1.dwUsed);
  try
    LbBiAddByte(tmp, cPREPEND_ARRAY, N2);
    LbBiAdd(N1, tmp, sum);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiSubByDigit(N1 : LbInteger; N2 : byte; var Sum : LbInteger);
var
  tmp : LbInteger;
begin
  LbBiInit(tmp, N1.dwUsed);
  try
    LbBiAddByte(tmp, cPREPEND_ARRAY, N2);
    LbBiSub(N1, tmp, sum);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddByDigitInPlace(var N1 : LbInteger; N2 : byte);
var
  sum : LbInteger;
begin
  LbBiInit(sum, N1.dwUsed);
  try
    LbBiAddByDigit(N1, N2, sum);
    LbBiClear(N1);
    N1.dwUsed := sum.dwUsed;
    N1.bSign := sum.bSign;
    if (N1.IntBuf.dwLen < sum.IntBuf.dwLen) then
      LbBiRealloc(N1, sum.IntBuf.dwLen);

    LbBiCopy(N1 , sum, sum.dwUsed);
  finally
    LbBiFree(sum);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiSubByDigitInPlace(var N1 : LbInteger; N2 : byte);
var
  diff : LbInteger;
begin
  LbBiInit(diff, N1.dwUsed);
  try
    LbBiSubByDigit(N1, N2, diff);
    LbBiClear(N1);
    N1.dwUsed := diff.dwUsed;
    N1.bSign := diff.bSign;
    if (N1.IntBuf.dwLen < diff.IntBuf.dwLen) then
      LbBiRealloc(N1, diff.IntBuf.dwLen);

    LbBiCopy(N1 , diff, diff.dwUsed);
  finally
    LbBiFree(diff);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiReverseBytes(N1 : LbInteger; var N2 : LbInteger);
var
  tmp_ptr : pByte;
  cnt : integer;                                                          {!!03}
begin
  tmp_ptr := N2.IntBuf.pBuf;
  FillChar(N2, SizeOf(N2), $00);
  N2.IntBuf.pBuf := tmp_ptr;
  N2.bSign := N1.bSign;
  N2.dwUsed := 0;
  if (N2.IntBuf.dwLen < N1.IntBuf.dwLen) then
    LbBiRealloc(N2, N1.IntBuf.dwLen);
  for cnt := N1.dwUsed downto 1 do begin
    LbBiAddByte(N2 , cAPPEND_ARRAY, LbBiGetByteValue(N1, cnt));
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiReverseBytesInPlace(var N1 : LbInteger);
var
  rev : LbInteger;
begin
  LbBiInit(rev, N1.IntBuf.dwLen);
  try
    LbBiReverseBytes  (N1, rev);
    LbBiClear(N1);
    N1.dwUsed := rev.dwUsed;
    N1.bSign := rev.bSign;
    LbBiCopy(N1, rev, rev.dwUsed);
  finally
    LbBiFree(rev);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiReverseAllBits(N1 : LbInteger; var N2 : LbInteger);
var
  i : integer;                                                            {!!03}
  byt_ptr : pByte;
begin
  LbBiReverseBytes(N1, N2);
  byt_ptr := N2.IntBuf.pBuf;
  for i := 1 to N2.dwUsed do begin
    byt_ptr^ := LbBiReverseBits(byt_ptr^);
    Inc(Longint(byt_ptr));
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiReverseBitsInPlace(var N1 : LbInteger);
var
  rev : LbInteger;
begin
  LbBiInit(rev, N1.IntBuf.dwLen);
  try
    LbBiReverseAllBits(N1, rev);
    LbBiClear(N1);
    N1.dwUsed := rev.dwUsed;
    N1.bSign := rev.bSign;
    LbBiCopy(N1, rev, rev.dwUsed);
  finally
    LbBiFree(rev);
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddBuf(var N1 : LbInteger; place : integer; buf : pByte;    {!!03}
                       length : Integer);
var
  totalLen : integer;                                                     {!!03}
  ptr : pByte;
begin

  if (place = cAPPEND_ARRAY) then begin
    totalLen := succ(N1.dwUsed + integer(length));                        {!!03}
    if (totalLen > N1.IntBuf.dwLen) then
      LbBiRealloc(N1, totalLen);
    ptr := N1.IntBuf.pBuf;
    inc(ptr, N1.dwUsed);
    move(buf^, ptr^, length);
    inc(N1.dwUsed, length);
  end else begin
    totalLen := pred(place) + integer(length);                            {!!03}
    if (totalLen > N1.IntBuf.dwLen) then
      LbBiRealloc(N1, totalLen);
    ptr := N1.IntBuf.pBuf;
     inc(ptr, pred(place));
    move(buf^, ptr^, length);
    if (N1.dwUsed < totalLen) then
      N1.dwUsed := totalLen;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddWord(var N1 : LbInteger; place : integer; N2 : word);    {!!03}
begin
  LbBiAddBuf(N1, place, @N2, SizeOf(word));
end;
{ ------------------------------------------------------------------- }
procedure LbBiAddDWord(var N1 : LbInteger; place : integer; N2 : integer);{!!03}
begin
  LbBiAddBuf(N1, place, @N2, SizeOf(integer));                            {!!03}
end;
{ ------------------------------------------------------------------- }
procedure LbBiCopyBigInt2Buf(N1 : LbInteger; place : integer; buf : pByte;{!!03}
                             length : Integer);
var
  ptr : pByte;
begin
  ptr := N1.IntBuf.pBuf;
  inc(ptr, pred(place));
  move(ptr^, buf^, length);
end;
{ ------------------------------------------------------------------- }
function LbBiCheckSimplePrimes(N1 : LbInteger) : Boolean;
  { returns true if N1 is not divisible by simple prime }
var
  cnt : Integer;
  quotient : LbInteger;
  N2 : LbInteger;
  remBN : LbInteger;
begin
  LbBiInit(quotient, N1.dwUsed);
  LbBiInit(N2 , 2);
  LbBiInit(remBN, N1.dwUsed);
  try
    for cnt := 0 to cTotalSimple2KPrimes do begin
      LbBiClear(N2);
      LbBiAddWord(N2, cPREPEND_ARRAY, SimplePrimes[ cnt ]);
      if LbBiCompare( N1, N2 ) = cEQUAL_TO then
        break;
      LbBiDiv(N1, N2, quotient, remBN);
      if (not LbBiIsZero(quotient)) and
        (not LbBiIsOne(quotient))  and LbBiIsZero(remBN) then begin
        Result := False;
        exit;
      end;
    end;
    Result := True;
  finally
    LbBiFree(quotient);
    LbBiFree(N2);
    LbBiFree(remBN);
  end;
end;
{ ------------------------------------------------------------------- }
function LbBiIsCompositFast(N1 : LbInteger; n : Integer) : Boolean;
var
  w : LbInteger;
  wMinus1 : LbInteger;
  m : LbInteger;
  b : LbInteger;
  z : LbInteger;
  a : Integer;
  j : Integer;
  i : Integer;
  one : LbInteger;
  random : TLbRandomGenerator;
  Buf : pByte;
  len : Integer;
begin
  len := (N1.dwUsed div 2) + 1;
  random := TLbRandomGenerator.create;
  Buf := pByte(AllocMem(len));
  LbBiInit(w, N1.dwUsed);
  LbBiInit(wMinus1, N1.dwUsed);
  LbBiInit(m, N1.dwUsed);
  LbBiInit(b, len);
  LbBiInit(z, N1.dwUsed);
  LbBiInit(one, 2);
  Result := True;
  try
    i := 1;

    { find w = 1 + (2^a) * m }
    {   where m is odd and 2^a is the largest power of 2 dividing w - 1 }
    LbBiCopy(w, N1, N1.dwUsed);
    LbBiSubByDigit(w, $01, wMinus1);
    if LbBiIsZero(wMinus1) then exit;

    LbBiCopy(m, wMinus1, wMinus1.dwUsed);

    a := 0;
    while(not LbBiGetBit(wMinus1, a))do begin
      LbBiShr(m, 1);
      if LbBiIsZero(m) then exit;
      inc(a);
    end;

    while True do begin
      { generate random number b: 1 < b < w }
      LbBiAddByte(one, cPREPEND_ARRAY, $01);
      while True do begin
        random.RandomBytes(Buf^, len);
        LbBiAddBuf(b, cPREPEND_ARRAY, Buf, len);
        if (LbBiCompare(one, b) <> cLESS_THAN)or
          (LbBiCompare(b, w) <> cLESS_THAN) then
            continue;
        break;
      end;

      j := 0;

      { z = b^m mod w }
      LbBiPowerAndMod(b, m, w, z);

      while True do begin
        { if j = 0 and z = 1 or z = w - 1 }
        if ((j = 0) and LbBiIsOne(z))or
          (LbBiCompare(z, wMinus1) = cEQUAL_TO) then begin
          if i < n then begin { inc i and start over }
            inc(i);
            break;
          end else begin { probably prime }
            Result := False;
            exit;
          end;
        end else begin
          if (j > 0) and (LbBiIsOne(z)) then { not prime }
            exit
          else begin
            inc(j);
            if (j < a) then begin
              LbBiMultInPlace(z, z);
              LbBiModInPlace(z, w);
            end else begin { not prime }
              exit;
            end;
          end;
        end;
      end;
    end;

  finally
    FreeMem(Buf, len);
    LbBiFree(one);
    LbBiFree(b);
    LbBiFree(m);
    LbBiFree(w);
    LbBiFree(z);
    LbBiFree(wMinus1);
    random.Free;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiRandomPrime(var N1 : LbInteger; Iterations : Byte);
var
  tmp_byt : byte;
  Buf : pByte;
  len : Integer;
  passed : Boolean;
  random : TLbRandomGenerator;
begin
  random := TLbRandomGenerator.create;
  passed := False;
  len    := N1.IntBuf.dwLen;
  Buf   := pByte(AllocMem(len));
  try
    while(not passed)do begin
      fillchar(Buf^, len, $00);
      random.RandomBytes(Buf^, len);

      LbBiAddBuf(N1, cPREPEND_ARRAY, Buf, len);

      { make it odd }
      tmp_byt := LbBiGetByteValue(N1, 1);
      tmp_byt := tmp_byt or $01;
      LbBiAddByte(N1, 1, tmp_byt);

      { make sure it is a big number }
      tmp_byt := LbBiGetByteValue(N1, N1.dwUsed);
      tmp_byt := tmp_byt or $80;
      LbBiAddByte(N1, N1.dwUsed, tmp_byt);

      repeat
        if LbBiCheckSimplePrimes(N1) then
          if (not LbBiIsCompositFast(N1, Iterations)) then begin
            passed := True;
            break;
          end;
        LbBiAddByDigitInPlace(N1, 2);
      until N1.dwUsed > integer(len);                                     {!!03}
    end;
  finally
    FreeMem(Buf, len);
    random.Free;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiRandomSimplePrime(var N1 : LbInteger);
var
  x : Word;
  RG : TLbRandomGenerator;
begin
  RG := TLbRandomGenerator.create;
  try
    repeat
      RG.RandomBytes(x, SizeOf(x));
      x := x and $0FFF;
    until(x > 3) and (x <= High(SimplePrimes));
    LbBiAddWord(N1, cPREPEND_ARRAY, SimplePrimes[x]);
  finally
    RG.Free;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiRandomBytes(var N1 : LbInteger; Count : Cardinal);
var
  RG : TLbRandomGenerator;
begin
  LbBiClear(N1);
  LbBiReAlloc(N1, Count);
  RG := TLbRandomGenerator.create;
  try
    RG.RandomBytes(N1.IntBuf.pBuf^, Count);
    N1.dwUsed := Count;
  finally
    RG.Free;
  end;
end;
{ ------------------------------------------------------------------- }
procedure LbBiExtendedEuclid(var u : LbInteger; var v : LbInteger;
                              var u1 : LbInteger; var u2 : LbInteger;
                              var GCD : LbInteger);
var

  t1 : LbInteger;
  t2 : LbInteger;
  t3 : LbInteger;
  zero : LbInteger;
  k : Integer;

  tmp : LbInteger;
begin

  LbBiVerify(u);
  LbBiVerify(v);
  LbBiPrepare(u, v, u1);
  LbBiPrepare(u, v, u2);
  LbBiPrepare(u, v, GCD);

  LbBiClear(u1);
  LbBiClear(u2);
  LbBiClear(GCD);

  LbBiInit(tmp, cDEFAULT_PRECISION);
  LbBiInit(t1, cDEFAULT_PRECISION);
  LbBiInit(t2, cDEFAULT_PRECISION);
  LbBiInit(t3, cDEFAULT_PRECISION);
  LbBiInit(zero, 1);

  try
    LbBiAddByte(zero, cPREPEND_ARRAY, $00);

    k := 0;
    while((LbBiIsEven(u)) and (LbBiIsEven(v)))do begin
      LbBiShr(u, 1);
      LbBiShr(v, 1);
      k := 1;
    end;

    if (LbBiCompare(u, v) = cLESS_THAN) then begin
      LbBiSwap(u, v);
    end;

    { u1 = 1 }
    LbBiAddByte(u1, cPREPEND_ARRAY, $01);
    { u2 = 0 }
    LbBiAddByte(u2, cPREPEND_ARRAY, $00);
    { GCD = u }
    LbBiCopy(GCD, u, u.dwUsed);
    { t1 = v }
    LbBiCopy(t1, v, v.dwUsed);
    { t2 = u-1 }
    LbBiClear(tmp);
    LbBiSubByDigit(u, $01, tmp);
    LbBiCopy(t2, tmp, tmp.dwUsed);
    { t3 = v }
    LbBiCopy(t3, v, v.dwUsed);

    repeat { while t3 > 0 }
      repeat { while LbBiIsEven(GCD) }
        if (LbBiIsEven(GCD)) then begin
          if (LbBiIsOdd(u1) or LbBiIsOdd(u2)) then begin
            LbBiAddInPlace(u1, v);
            LbBiAddInPlace(u2, u);
          end;
          LbBiShr(u1, 1);
          LbBiShr(u2, 1);
          LbBiShr(GCD, 1);
        end;
        if (LbBiIsEven(t3) or
          (LbBiCompare(GCD, t3) = cLESS_THAN)) then begin
          LbBiSwap(u1, t1);
          LbBiSwap(u2, t2);
          LbBiSwap(GCD, t3);
        end;
      until(LbBiIsOdd(GCD));

      { while(u1 < t1)or(u2 < t2) }
      while((LbBiCompare(u1, t1) = cLESS_THAN) or
            (LbBiCompare(u2, t2) = cLESS_THAN))do begin
        LbBiAddInPlace(u1, v);
        LbBiAddInPlace(u2, u);
      end;
      LbBiSubInPlace(u1, t1);
      LbBiSubInPlace(u2, t2);
      LbBiSubInPlace(GCD, t3);
    until (LbBiCompare(t3, zero) = cLESS_THAN) or
          (LbBiCompare(t3, zero) = cEQUAL_TO );

    { while(u1 <= v) and (u2 <= u) }
    while(((LbBiCompare(u1, v) = cGREATER_THAN) or
           (LbBiCompare(u1, v) = cEQUAL_TO)) and
          ((LbBiCompare(u2, u) = cGREATER_THAN) or
           (LbBiCompare(u2, u) = cEQUAL_TO)))do begin
      LbBiSubInPlace(u1, v);
      LbBiSubInPlace(u2, u);
    end;
    LbBiShl(u1, k);
    LbBiShr(u2, k);
    LbBiShr(GCD, k);
  finally
    LbBiFree(tmp);
    LbBiFree(t1);
    LbBiFree(t2);
    LbBiFree(t3);
    LbBiFree(zero);
  end;
end;
{ ------------------------------------------------------------------- }
function LbBiModInv(e : LbInteger; _mod : LbInteger; var d : LbInteger) : Boolean;
var
  v : LbInteger;
  u : LbInteger;
  a : LbInteger;
  b : LbInteger;
  gcd : LbInteger;
begin
  LbBiVerify(e);
  LbBiVerify(_mod);
  LbBiPrepare(e, _mod, d);

  LbBiInit(u, cUSE_DEFAULT_PRECISION);
  LbBiInit(v, cUSE_DEFAULT_PRECISION);
  LbBiInit(a, cUSE_DEFAULT_PRECISION);
  LbBiInit(b, cUSE_DEFAULT_PRECISION);
  LbBiInit(gcd, cUSE_DEFAULT_PRECISION);
  Result := False;
  try
    { LbBiExtendedEuclid may switch the first two so send a local copy }
    LbBiCopy(u, e, e.dwUsed);
    LbBiCopy(v, _mod, _mod.dwUsed);
    LbBiExtendedEuclid(u, v, a, b, gcd);
    if (LbBiIsOne(gcd)) then begin
      { numbers valid }
      LbBiSub(u, b, d);
      Result := True;
    end;
  finally
    LbBiFree(u);
    LbBiFree(v);
    LbBiFree(a);
    LbBiFree(b);
    LbBiFree(gcd);
  end;
end;


{ == TLbLbInteger ========================================================= }
constructor TLbBigInt.Create(ALen : Integer);
var
  prec : Integer;
begin
  if (Alen < 1) then
    prec := cUSE_DEFAULT_PRECISION
  else
    prec := ALen;

  LbBiInit(FI, prec);
  inherited Create;
end;
{ ------------------------------------------------------------------- }
destructor TLbBigInt.Destroy;
begin
  LbBiFree(FI);
  inherited Destroy;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.SetSign(value : Boolean);
begin
  LbBiVerify(FI);
  if (value <> FI.bSign) then begin
    FI.bSign := value;
  end;
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.getSign : Boolean;
begin
  LbBiVerify(FI);
  Result := FI.bSign;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Add(I2 : TLbBigInt);
var
  tmp : LbInteger;
begin
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    LbBiAddInPlace(FI, tmp);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Subtract(I2 : TLbBigInt);
var
  tmp : LbInteger;
begin
  LbBiVerify(FI);
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    LbBiSubInPlace(FI, tmp);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Multiply(I2 : TLbBigInt);
var
  tmp : LbInteger;
begin
  LbBiVerify(FI);
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    LbBiMultInPlace(FI, tmp);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Divide(I2 : TLbBigInt);
var
  tmp : LbInteger;
  rem : LbInteger;
begin
  LbBiVerify(FI);
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  LbBiInit(rem, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    LbBiDivInPlace(FI, tmp, rem);
  finally
    LbBiFree(tmp);
    LbBiFree(rem);
  end;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Modulus(I2 : TLbBigInt);
var
  tmp : LbInteger;
begin
  LbBiVerify(FI);
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    LbBiModInPlace(FI, tmp);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.SubtractByte(b : byte);
begin
  LbBiVerify(FI);
  LbBiSubByDigitInPlace(FI, b);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.MultiplyByte(b : byte);
begin
  LbBiVerify(FI);
  LbBiMulByDigitInPlace(FI, b);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.DivideByte(b : byte);
var
  rem : byte;
begin
  LbBiVerify(FI);
  LbBiDivByDigitInPlace(FI, b, rem);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.ModByte(b : byte);
var
  rem : byte;
begin
  LbBiVerify(FI);
  LbBiDivByDigitInPlace(FI, b, rem);
  LbBiClear(FI);
  LbBiAddByte(FI, cPREPEND_ARRAY, rem);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.AddByte(b : byte);
begin
  LbBiVerify(FI);
  LbBiAddByDigitInPlace(FI, b);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Clear;
begin
  LbBiClear(FI);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Trim;
begin
  LbBiVerify(FI);
  LbBiTrimSigZeros(FI);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.Compare(I2 : TLbBigInt) : ShortInt;
var
  tmp : LbInteger;
begin
  LbBiVerify(FI);
  LbBiInit(tmp, I2.Int.dwUsed);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    Result := LbBiCompare(FI, tmp); 
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.Abs(I2 : TLbBigInt): ShortInt;
var
  tmp : LbInteger;
begin
  LbBiVerify(FI);
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, I2.Int, I2.Int.dwUsed);
    LbBiVerify(tmp);
    Result := LbBiAbs(FI, tmp);
  finally
    LbBiFree(tmp);
  end;
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.IsZero : Boolean;
begin
  LbBiVerify(FI);
  Result := LbBiIsZero(FI);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.IsOne : Boolean;
begin
  LbBiVerify(FI);
  Result := LbBiIsOne(FI);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.IsComposite(Iterations : Cardinal) : Boolean;
begin
  LbBiVerify(FI);
  Result := true;
  if LbBiCheckSimplePrimes(FI) then
     if (not LbBiIsCompositFast(FI, Iterations)) then
         Result := false;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Copy(I2 : TLbBigInt);
begin
  Clear;
  LbBIMove(FI, I2.Int, cAPPEND_ARRAY, I2.Size);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.CopyLen(I2 : TLbBigInt; Len : Integer);
begin
  Clear;
  LbBIMove(FI, I2.Int, cAPPEND_ARRAY, Len);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.CopyByte(b : byte);
begin
  Clear;
  LbBiAddByte(FI, cPREPEND_ARRAY, b);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.CopyWord(w : word);
begin
  Clear;
  LbBiAddWord(FI, cPREPEND_ARRAY, w);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.CopyDWord(d : dword);
begin
  Clear;
  LbBiAddDWord(FI, cPREPEND_ARRAY, d);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.CopyBuffer(const Buf; BufLen : Integer);
begin
  Clear;
  LbBiAddBuf(FI, cPREPEND_ARRAY, @Buf, BufLen);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Append(I : TLbBigInt);
begin
  LbBIMove(FI, I.Int, cAPPEND_ARRAY, I.Size);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.AppendByte(b : byte);
begin
  LbBiAddByte(FI, cAPPEND_ARRAY, b);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.AppendWord(w : word);
begin
  LbBiAddWord(FI, cAPPEND_ARRAY, w);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.AppendDWord(d : dword);
begin
  LbBiAddDWord(FI, cAPPEND_ARRAY, d);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.AppendBuffer(const Buf; BufLen : Integer);
begin
  LbBiAddBuf(FI, cAPPEND_ARRAY, @Buf, BufLen);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Prepend(I : TLbBigInt);
begin
  LbBIMove(FI, I.Int, cPREPEND_ARRAY, I.Size);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.PrependByte(b : byte);
begin
  LbBiAddByte(FI, cPREPEND_ARRAY, b);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.PrependWord(w : word);
begin
  LbBiAddWord(FI, cPREPEND_ARRAY, w);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.PrependDWord(d : dword);
begin
  LbBiAddDWord(FI, cPREPEND_ARRAY, d);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.PrependBuffer(const Buf; BufLen : Integer);
begin
  LbBiAddBuf(FI, cPREPEND_ARRAY, @Buf, BufLen);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.RandomPrime(Iterations : Byte);
begin
  LbBiRandomPrime(FI, Iterations);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.RandomSimplePrime;
begin
  LbBiRandomSimplePrime(FI);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.RandomBytes(Count : Cardinal);
begin
  LbBiRandomBytes(FI, Count);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.ToBuffer(var Buf; BufLen : Integer ) : integer;
var
  len : Integer;
begin
//  LbBiVerify(FI);
  len := Min(FI.dwUsed, BufLen);
  result := len;
  LbBiCopyBigInt2Buf(FI, cPREPEND_ARRAY, @Buf, len);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.ReverseBits;
begin
  LbBiVerify(FI);
  LbBiReverseBitsInPlace(FI);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.ReverseBytes;
begin
  LbBiVerify(FI);
  LbBiReverseBytesInPlace(FI);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.IsOdd : Boolean;
begin
  LbBiVerify(FI);
  Result := LbBiIsOdd(FI);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.IsEven : Boolean;
begin
  LbBiVerify(FI);
  Result := LbBiIsEven(FI);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.GetBit(bit : Integer) : Boolean;
begin
  LbBiVerify(FI);
  Result := LbBiGetBit(FI, bit);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Shr_(_shr : Integer);
begin
  LbBiVerify(FI);
  LbBiShr(FI, _shr);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.Shl_(_shl : Integer);
begin
  LbBiVerify(FI);
  LbBiShl(FI, _shl);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.XOR_(I2 : TLbBigInt);
begin
  LbBiVerify(FI);
  LbBiXORInPlace(FI, I2.Int);
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.OR_(I2 : TLbBigInt);
begin
  LbBiVerify(FI);
  LbBiORInPlace(FI, I2.Int);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.ModInv(Modulus : TLbBigInt) : Boolean;
var
  tmp : LbInteger;
  x : LbInteger;
begin
  LbBiInit(tmp, cUSE_DEFAULT_PRECISION);
  LbBiInit(x, cUSE_DEFAULT_PRECISION);
  try
    LbBiCopy(tmp, Modulus.Int, Modulus.Int.dwUsed);
    LbBiVerify(tmp);

    Result := LbBiModInv(FI, tmp, x);
    LbBiClear(FI);
    LbBiCopy(FI, x, x.dwUsed);
  finally
    LbBiFree(tmp);
    LbBiFree(x);
  end;
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.GetSize : integer;                                     {!!03}
begin
  Result := FI.dwUsed;
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.GetIntStr : string;
begin
  Result := BufferToHex(IntBuf^, FI.dwUsed);
end;
{ ------------------------------------------------------------------- }
function TLbBigInt.GetIntBuf : pByte;
begin
  Result := FI.IntBuf.pBuf;
end;
{ ------------------------------------------------------------------- }
procedure TLbBigInt.PowerAndMod(Exponent : TLbBigInt; Modulus : TLbBigInt);
begin
  LbBiPowerAndModInPLace(FI, Exponent.Int, Modulus.Int);
end;

{ ------------------------------------------------------------------- }
function TLbBigInt.GetByteValue( place : integer ) : Byte;
begin
  LbBiVerify(FI);
  result := LbBiGetByteValue( FI, place );
end;
end.




