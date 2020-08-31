// lr3_HMAC.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h> 
#include <fstream>
#include <string>


#pragma comment (lib, "Crypt32.lib")

using namespace std;

// получение дeскриптора криптопровайдера
void initCryptProv(HCRYPTPROV* hProv)
{
    if (!CryptAcquireContext(hProv, NULL, NULL,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        cout << " !!!Error CryptAcquireContext!!!\n";
        return;
    }

    cout << "Cryptographic provider initialized\n";
}


void createHashKey(HCRYPTPROV *hProv, HCRYPTHASH *hHash, HCRYPTKEY *hKey)
{
    BYTE Data[] = { 0x70,0x61,0x73,0x77,0x6F,0x72,0x64 };
    //create hashKey
    if (!CryptCreateHash(*hProv, CALG_MD5, 0, 0, hHash))
    {
        cout << "Error in CryptCreateHash\n";
        return;
    }
    cout << "CryptCreateHash succsess: "<< *hHash<< endl;

    if (!CryptHashData(*hHash, Data, sizeof(Data), 0))
    {
        cout << "Error in CryptHashData\n";
        return;
    }
    cout << "CryptHashData succsess\n";

    if (!CryptDeriveKey(*hProv, CALG_RC4, *hHash, 0, hKey))
    {
        cout << "Error in CryptDeriveKey\n";
        return;
    }
    cout << "CryptDeriveKey succsess: "<<*hKey<< endl;
}

void createHMAC(HCRYPTPROV *hProv, HCRYPTKEY *hKey)
{
    HCRYPTHASH hHash = NULL;
    HCRYPTHASH hHmacHash = NULL;
    DWORD dwDataLen = 0;
    BYTE Data2[] = {0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65};
    HMAC_INFO HmacInfo;
   
    //обнуление структуры HMAC_INFO и использование MD5
    ZeroMemory(&HmacInfo, sizeof(HmacInfo));
    HmacInfo.HashAlgid = CALG_MD5;

    // создаем хэш объект
    if (!CryptCreateHash(*hProv, CALG_HMAC, *hKey, 0, &hHmacHash))
    {
        cout << "Error in CryptCreateHash (createHMAC)\n";
        return;
    }
    cout << "hmachash :" << hHmacHash << endl;
    if (!CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0))
    {
        cout << "Error in CryptSetHashParam(createHMAC)\n";
        return;
    }
   
    if (!CryptHashData(hHmacHash, Data2, sizeof(Data2), 0))
    {
        cout << "Error in CryptHashData (createHMAC)\n";
        return;
    }

    // выделяем память и получаем HMAC
    if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0))
    {
        cout << "Error in CryptGetHashParam (createHMAC)\n";
        return;
    }
   BYTE *pbHash = (BYTE*)malloc(dwDataLen);
    if (pbHash == NULL)
    {
        cout << "unable to allocate memory (createHMAC)\n";
        return;
    }
    if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0))
    {
        cout << "Error in  CryptGetHashParam(createHMAC)\n";
        return;
    }
    cout << "The hash is: ";
    for (DWORD i = 0; i < dwDataLen; i++)
        cout << pbHash[i];
    
}

void myHMAC(HCRYPTPROV* hProv)
{
    DWORD dwDataLen = 0;
    HCRYPTHASH hHmacHash = NULL;
    PBYTE pbHash = NULL;
    HMAC_INFO HmacInfo;
    ZeroMemory(&HmacInfo, sizeof(HmacInfo));
    HmacInfo.HashAlgid = CALG_MD5;

    BYTE Data[] = { 0x70,0x61,0x73,0x77,0x6F,0x72,0x64 };
    BYTE Data2[] = { 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 };
    
    //константы для HMAC
    BYTE C1[] = { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
    BYTE C2[] = { 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C };

    BYTE Si[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE S0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    // xor(Data, C1), xor(Data,C2)
    for (BYTE i = 0; i < sizeof(Data); i++)
    {
        Si[i] = Data[i] ^ C1[i];
        S0[i] = Data[i] ^ C2[i];

    }

    BYTE concatenation1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Si|| Data2
    for (BYTE i = 0; i < sizeof(concatenation1); i++)
    {
        if (i < sizeof(Si))
            concatenation1[i] = Si[i];
        else
            concatenation1[i] = Data2[i - sizeof(Si)];
    }
    // MD5(Si || Data2)
    CryptCreateHash(*hProv, CALG_MD5, 0, 0, &hHmacHash);
    CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0);
    CryptHashData(hHmacHash, concatenation1, sizeof(concatenation1), 0);
    CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0);
    pbHash = (BYTE*)malloc(dwDataLen);
    CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0);
    
    // MD5 должен вернуть 16 байтовое значение, поэтому  concatenation2 должен быть 16+7 =23
    BYTE concatenation2[]= { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    // MD5(Si || Data2) || S0
    for (BYTE i = 0; i < sizeof(concatenation2); i++)
    {
        if (i < sizeof(S0))
            concatenation2[i] = S0[i];
        else
            concatenation2[i] = pbHash[i - sizeof(S0)];
    }

    //MD5( MD5(Si || Data2) || S0)
    CryptCreateHash(*hProv, CALG_MD5, 0, 0, &hHmacHash);
    CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0);
    CryptHashData(hHmacHash, concatenation2, sizeof(concatenation2), 0);
    CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0);
    pbHash = (BYTE*)malloc(dwDataLen);
    CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0);

    //Выведем хэш 
    cout << "\n HMAC Hash: "<< pbHash <<endl;
    
}

int main()
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;
    PBYTE pbHash = NULL;
    DWORD dwDatalen = 0;
    initCryptProv(&hProv);
    createHashKey(&hProv,&hHash,&hKey);
    createHMAC(&hProv, &hKey);
    myHMAC(&hProv);
    
}

