#include<bits/stdc++.h>
#include<sstream>
#define byte unsigned short
#define WORD unsigned int

using namespace std;
//Tables
//============================================
//Sbox Encryption-short size is 2 bytes
short sBox[] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
//
short Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
//=============================================
//Prototypes
//=============================================
void keyExpand(byte key[16],WORD w[44]);
WORD subWord(WORD t);
WORD RotWord(WORD t);
void getKeyFromWord(WORD w[4],byte key[16]);
byte subBytes(byte t);
void shiftRows(byte roudnInput[16],byte rslt[16]);
byte GfMul(byte a , byte b);
void addRoundKey(byte roundInput[16],byte roundKey[16],byte rslt[16]);
void readInput(byte plainText[16],byte key[16],bool v);
void visualize(string s, int roundNumber,byte v[16]);
//=============================================
//Implementations
//=============================================

//This implementation is inspired by the code present in the slides
void keyExpand(byte key[16],WORD w[44]){
    WORD temp;
    for (int i = 0; i < 4; ++i) {
        WORD a=0;
        for (int j = 0; j < 4; ++j) a|=key[4*i+j]<<(j*8);
        w[i]=a;
    }
    for (int i = 4; i < 44; ++i) {
        temp=w[i-1];
        if(i%4==0) temp=subWord(RotWord(temp))^(Rcon[int(i/4)-1]);
        w[i]=temp^w[i-4];
    }
}

void getKeyFromWord(WORD w[4],byte key[16]){
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            key[4*i+j]=w[i]>>(8*j)&(0xff);
        }
    }
}

WORD subWord(WORD t){
    WORD rslt=0;
    for (int i = 0; i < 4; ++i) {
       rslt|=subBytes((t>>(i*8))& 0xff)<<(i*8);
    }
    return rslt;
}

WORD RotWord(WORD t){
    return (t>>8) | (t<<(24));
}

byte subBytes(byte t){
    byte x=t&0x0f;
    byte y=(t>>4)&0x0f;
    return sBox[y*16+x];
}

void shiftRows(byte roudnInput[16],byte rslt[16]){
    WORD temp[4];
    for (int i = 0; i < 4; ++i) {
        WORD a=0;
        for (int j = 0; j < 4; ++j) {
            a|=roudnInput[4*j+i]<<(j*8);
        }
        temp[i]=a>>(i*8)|a<<(32-i*8);
    }
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            rslt[4*i+j]=(temp[j]>>(i*8))&((0xff));
        }
    }
}

//gf(2^8) addition process is a simple xor
void mixColumns(byte roundInput[16],byte rslt[16]){
    for (int i = 0; i <4; ++i) {
        rslt[4*i]=GfMul(0x02,roundInput[4*i])^GfMul(0x03,roundInput[4*i+1])^roundInput[4*i+2]^roundInput[4*i+3];
        rslt[4*i+1]=GfMul(0x02,roundInput[4*i+1])^GfMul(0x03,roundInput[4*i+2])^roundInput[4*i]^roundInput[4*i+3];
        rslt[4*i+2]=GfMul(0x02,roundInput[4*i+2])^GfMul(0x03,roundInput[4*i+3])^roundInput[4*i]^roundInput[4*i+1];
        rslt[4*i+3]=GfMul(0x03,roundInput[4*i])^GfMul(0x02,roundInput[4*i+3])^roundInput[4*i+1]^roundInput[4*i+2];
    }

}

//This implementation is Inspired by Peasant's Multiplication algorithm
byte GfMul(byte a, byte b){
     byte p=0;
     for (int i = 0; i < 8; ++i) {
         if(b&1) p^=a;
         if(a & 0x80)   a=(a<<1)^0x11b; //Hex 0x11B is the representation of x^8 + x^4 + x^3 + x + 1
         else a=a<<1;
         b>>=1;
     }
     return p;
}

void addRoundKey(byte roundInput[16],byte roundKey[16],byte rslt[16]){
    for (int i = 0; i < 16; ++i) {
        rslt[i]=roundInput[i]^roundKey[i];
    }
}

void readInput(byte plainText[16],byte key[16],bool v){
    string p,k;
    cout<<"Plain Text:"; cin>>p;
    cout<<endl<<"Key: ";    cin>>k;
    stringstream ss; int c=0;
    for(int i=0;i<4;i++)
        for(int j=0;j<4;j++, c+=2){
          ss << hex << p.substr(c, 2);
          ss >> plainText[4*i+j];
          ss.clear();
          ss << hex << k.substr(c,2);
          ss >> key[4*i+j];
          ss.clear();
        }
    cout<<"Do You want to visualize every Step? (0/1)"<<endl;
    cin>>v;
}

void visualize(string s, int roundNumber,byte v[16]){
    cout<<s<<roundNumber<<endl;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            cout<<hex<<v[4*i+j]<<"_";
        }
        cout<<endl;
    }
    cout<<"=================="<<endl;
}

//==============================================

int main(){

    byte key[16]; byte plainText[16]; bool v=false;
    readInput(plainText,key,v);

    WORD roundKeys[44];
    keyExpand(key,roundKeys);
    WORD round_0_WORD[4]={roundKeys[0],roundKeys[1],roundKeys[2],roundKeys[3]};
    byte round_0_Key[16];
    getKeyFromWord(round_0_WORD,round_0_Key);

    //Round 0
    byte c[16];
    addRoundKey(plainText,round_0_Key,c);

    //Round 1-9
    for (int r = 0; r < 9; ++r) {
        //Substitute Bytes
        for (int b = 0; b < 16; ++b)    c[b]=subBytes(c[b]);
        if(v) visualize("Sbox Out ",r,c);
        //Shift Rows
        byte shiftedC[16];
        shiftRows(c,shiftedC);

        if(v) visualize("shifted output",r,shiftedC);

        //mix Columns
        byte mixedC[16];
        mixColumns(shiftedC,mixedC);

        if(v) visualize("mixed output",r,mixedC);

        //Add Round Key
        WORD roundWORD[4]={roundKeys[4*(r+1)],roundKeys[4*(r+1)+1],roundKeys[4*(r+1)+2],roundKeys[4*(r+1)+3]};
        byte roundKey[16];
        getKeyFromWord(roundWORD,roundKey);

        if(v) visualize("Round Key",r,roundKey);
        addRoundKey(mixedC,roundKey,c);


        if(v) visualize("Output",r,c);
        if(v) cout<<"=================================================="<<endl;
    }

    //Round 10
    //Substitute Bytes
    for (int b = 0; b < 16; ++b)    c[b]=subBytes(c[b]);

    //Shift Rows
    byte shiftedC[16];
    shiftRows(c,shiftedC);
    //Add Round Key
    WORD roundWORD[4]={roundKeys[40],roundKeys[41],roundKeys[42],roundKeys[43]};
    byte roundKey[16];
    getKeyFromWord(roundWORD,roundKey);
    addRoundKey(shiftedC,roundKey,c);

    if(v) visualize("Final Output",10,c);

    cout<<"Cipher Text: ";
    for (int i = 0; i < 16; ++i) cout<<setfill('0')<<setw(2)<<hex<<c[i];
    cout<<endl;
    return 0;
}
