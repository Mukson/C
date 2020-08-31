#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h> 
#include <fstream>
#include <string>

#pragma comment (lib, "Crypt32.lib")

using namespace std;

#define MY_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CERT_STORE_NAME L"MY"
#define BLOCK_SIZE 15

struct Keies
{
    HCRYPTKEY PublicKey;
    HCRYPTKEY PrivateKey;
}KeyPair;

// открытие хранилища сертификатов
void open_cStore(HCRYPTPROV *hProv)
{
    HCERTSTORE hStore;
    PCCERT_CONTEXT hContext = NULL;
    LPTSTR pszName = new TCHAR[128];
    DWORD keySpec = 0;
    int i = 0; int certNum = 0;
        if (!(hStore = CertOpenSystemStoreA(NULL, "MY"))) 
        {
            cout << "!!!!err open store!!!\n"; cin.get(); return ;
        }
      
        while (hContext = CertEnumCertificatesInStore(hStore, hContext))
        {
            if (!CertGetNameStringW(hContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, pszName, 128))
            {
                cout << "!!!!err get name!!!!\n"; cin.get(); return ;
            }
            i++;
            cout << i << " " << pszName << '\n';
        }
        cout << "enter num of cert\n";
        cin >> certNum; hContext = NULL;
        for (i = 0; i < certNum; i++)
        {
                hContext = CertEnumCertificatesInStore(hStore, hContext);
        }
            delete[] pszName;
            if (hContext == NULL)
            {
                cout << "!! error getting cert!!!!!\n";
                cin.get(); return ;
            }

             // импортируем публичный ключ
          
            if (CryptImportPublicKeyInfo(*hProv, MY_TYPE, &hContext->pCertInfo->SubjectPublicKeyInfo,&KeyPair.PublicKey))
            {
                cout << "import public key: " << KeyPair.PublicKey << endl;
            }
            else { cout << "err import public key\n"; }
           
            //извлечение из сертификата контекста приватного ключа
            
            if (!CryptAcquireCertificatePrivateKey(hContext, NULL, NULL, hProv, &keySpec, NULL))
            {
                cout << "!!!!error getting private context!!!!!!!!!!\n";
                cout << hProv<<endl;
                
                return;
            }
            //извлечение закрытого ключа
            if (!CryptGetUserKey(*hProv, keySpec, &KeyPair.PrivateKey))
            {
                cout << "!!!!!err getting private key!!!!\n";
                
                return ;
            }
            else { cout << "import privateKey: " << KeyPair.PrivateKey << endl; }
            return;
 }

void file_crypt(HCRYPTKEY *hSessionKey)
{
    BYTE* pCryptBuf = 0;
    DWORD buflen;
    BOOL bRes;
    DWORD datalen;
    FILE* in; 
    if (fopen_s(&in, "D:\\text.txt", "r+b") !=0) { cout << "!!!!!Encrypt err read file!!!\n"; };
    FILE* out; 
    if (fopen_s(&out, "D:\\crypt.txt", "w+b")!=0 ) { cout << "!!!!!Encrypt err open file for writing!!!\n"; };
    int t = 0;
    //определяем размер буфера, необходимого для блоков длины BLOCK_SIZE
        buflen = BLOCK_SIZE;
    if(!CryptEncrypt(*hSessionKey,0,TRUE,0,NULL, &buflen,0))
    {
        cout << "!!!!!!CryptEncypt (bufSize) failed!!!\n";
        return;
    }
    // выделим память под буфер
    pCryptBuf = (BYTE*)malloc(buflen);
    while ((t = fread(pCryptBuf, sizeof byte, BLOCK_SIZE, in)))
    {
        datalen = t;
        bRes = CryptEncrypt(*hSessionKey, 0, TRUE, 0, pCryptBuf, &datalen, buflen);
        if (!bRes)
        {
            cout << "!!!!!!!CryptEncypt (encryption) faled!!!!\n";
            return;
        }
        fwrite(pCryptBuf, sizeof byte, datalen, out);
    }
    cout << "file encryption completed successfully\n";
    fclose(in); fclose(out);
    free(pCryptBuf);
}



void file_decrypt(HCRYPTKEY *hSessionKey)
{
    BYTE* pCryptBuf = 0;
    DWORD buflen;
    BOOL bRes;
    DWORD datalen;
    FILE* out; 
    if(fopen_s(&out, "D:\\decrypt.txt", "w+b") !=0) { cout << "!!!!Decrypt err open file for writing!!!\n"; };
    FILE* in; 
    if(fopen_s(&in, "D:\\crypt.txt", "r+b") !=0) { cout << "!!!!Decrypt err read file!!!!\n"; };
    int t = 0;

    //определяем размер буфера, необходимого для блоков длины BLOCK_SIZE
    
    datalen = BLOCK_SIZE;
   // bRes = CryptEncrypt(*hSessionKey, 0, TRUE, 0, NULL, &buflen, 0);
    pCryptBuf = (BYTE*)malloc(datalen);
    while ((t = fread(pCryptBuf, sizeof byte, datalen, in)))
    {
        buflen = t;
        bRes = CryptDecrypt(*hSessionKey, 0, TRUE, 0, pCryptBuf, &buflen);
        if (!bRes)
        {
            cout << "!!!!CryptDecrypt (buffer size) faled!!!!\n";
            return;
        }
        fwrite(pCryptBuf, sizeof byte, buflen, out);
    }
    cout << "file dencryption completed successfully\n";
    fclose(in); fclose(out);
    free(pCryptBuf);
}


void crypt_SessionKey(HCRYPTKEY *hSessionKey, HCRYPTKEY *hPublicKey, DWORD *dwBlobLength)
{
   // DWORD dwBlobLength = 0;
    BYTE* ppbKeyBlob; ppbKeyBlob = NULL;
    FILE* out;
    if (fopen_s(&out, "D:\\cryptKey.txt", "w+b") != 0) { cout << " !!!!err open file for writing crypt_sessionKey!!!\n"; };
   
    // определение размера bloba сессионного ключа
    if (CryptExportKey(*hSessionKey, *hPublicKey, SIMPLEBLOB, 0, 0, dwBlobLength)) 
    {
        cout << "size of the blob: " << *dwBlobLength << endl;
    }
    else
    { 
        cout<<"!!!err computing blob length!!!\n";
        return;
    }
    // распределение памяти для сессионного ключа
    if (ppbKeyBlob = (LPBYTE)malloc(*dwBlobLength))
    {
        cout << "memory has been allocated for the blob\n";
    }
    else
    {
        cout << "!!!err memory for key lengh!!!\n";
            return;
    }
    // шифрование сессионного ключа открытым
    if (CryptExportKey(*hSessionKey, *hPublicKey, SIMPLEBLOB, 0, ppbKeyBlob, dwBlobLength))
    {
        cout << "contents have been written to the blob\n";
    }
    else
    {
        cout << "!!!!couldn't get exporting key!!!\n";
        free(ppbKeyBlob);
        ppbKeyBlob = NULL;
        return;
    }
    //записываем сессионный ключ в файл
    if (fwrite(ppbKeyBlob, sizeof byte, *dwBlobLength, out))
    {
        cout << "the session key written to the file\n";
        fclose(out);
        return;
    }
    else
    {
        cout << "!!!!the session key couldn't be written to the file!!!!\n";
            return;
    }
}

void decrypt_SessionKey(HCRYPTPROV *hProv, DWORD *dwBlobLength, HCRYPTKEY *newKey)
{
    BYTE* ppbKeyBlob; ppbKeyBlob = NULL;
   
   
   FILE* in;
    if (fopen_s(&in, "D:\\cryptKey.txt", "r+b") != 0) { cout << "!!!! err open file for reading crypt_sessionKey!!!\n"; };
    
    
    // распределение памяти для сессионного ключа
    if (ppbKeyBlob = (LPBYTE)malloc(*dwBlobLength))
    {
        cout << "memory has been allocated for the blob: "<< *dwBlobLength<<endl;
    }
    else
    {
        cout << "!!!err memory for key lengh!!!\n";
        return;
    }

    //считывание сессионного ключа из файла
    if (fread(ppbKeyBlob, sizeof byte, *dwBlobLength, in))
       {
        
        cout << "the session key's been read from the file\n";
        fclose(in);
        }
    else
    {
        cout << "!!!!!the session key couldn't be read from the file!!!!\n ";
        return;
    }
    
    if (CryptImportKey(*hProv, ppbKeyBlob, *dwBlobLength, KeyPair.PrivateKey, 0, newKey))
    {
        cout << "the session key has been decrypted"<< endl;
        free(ppbKeyBlob);
    }
    else
    {
        cout << "!!!! session key decrypt error !!!\n";
        return;
    }

}
void initCryptProv(HCRYPTPROV *hProv)
{    
    if (!CryptAcquireContext(hProv, NULL, NULL,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        cout << " !!!Error CryptAcquireContext!!!\n";
        return;
    }

    cout << "Cryptographic provider initialized\n";
}

void gen_session_key(HCRYPTPROV *hProv, HCRYPTKEY *hSessionKey)
{     
    // Генерация сессионного ключа
    if (!CryptGenKey(*hProv, CALG_RC4,
        CRYPT_EXPORTABLE | CRYPT_ENCRYPT, hSessionKey))
    {
        cout<<"!!!Error CryptGenKey!!\n";
        return;
    }
    cout << "Session key generated: " << *hSessionKey<< endl;
}

int main()
{
    cout << "Hello, cryptoMan!\n";
    HCRYPTPROV hProv;
    HCRYPTKEY hSessionKey;
    HCRYPTKEY newKey;
    DWORD dwBlobLength;
    
    initCryptProv(&hProv);// Получение контекста криптопровайдера
    gen_session_key(&hProv, &hSessionKey);//генерация сессионного ключа
    open_cStore(&hProv);// открытие хранилища сертификатов
    file_crypt(&hSessionKey);// шифровка файла
    crypt_SessionKey(&hSessionKey, &KeyPair.PublicKey, &dwBlobLength);//шифрование сессионного ключа
    decrypt_SessionKey(&hProv, &dwBlobLength, &newKey);// расшифровка сессионного ключа
    file_decrypt(&newKey);

    CryptDestroyKey(hSessionKey);
    CryptReleaseContext(hProv, 0);
}

