#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h> 
#include <fstream>
#include <string>

#pragma comment (lib, "Crypt32.lib")

#define MY_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CERT_STORE_NAME L"MY"
#define SIGNER_NAME L"Labs"


using namespace std;

struct Keies
{
    HCRYPTKEY PublicKey;
    HCRYPTKEY PrivateKey;
}KeyPair;


void doHash(HCRYPTPROV* hProv, HCRYPTHASH *hHash)
{
    LPCWSTR hInFile = L"D:\HashFile.txt";
    HANDLE  hFile;
    DWORD dwlen;
    DWORD fsize; 

    // file for data
    if (!(hFile = CreateFileW(hInFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
    {
        cout << "!!!!!couldn't open file\n";
        return;
    }
    fsize = GetFileSize(hFile, &fsize);

    // Cоздание хеш - объекта
        if (!CryptCreateHash(*hProv, CALG_MD5, 0, 0, hHash))
        {
            cout<<"Error(CryptCreateHash)\n";
            return;
        }
    cout << "Hash created "<< *hHash << endl;

    // read the file
    BYTE* read = new BYTE[fsize + 8];
    if (!::ReadFile(hFile, read, fsize, &dwlen, NULL))
    {
        cout << "!!!! error reading file!!!\n";
        return;
    }
   
    //passing hash data to hash-object
    if (!CryptHashData(*hHash, read, dwlen, 0))
    {
        cout << "!!!CryptHashData error!!!!!\n";
        return;
    }
    cout << "Hash data loaded: " << read << endl;

    //get hash
     DWORD count = 0;
    if (!CryptGetHashParam(*hHash, HP_HASHVAL, NULL, &count, 0))
    {
        cout << "!!!!!CryptGetHashParam error!!!!!!\n";
        return;
    }

    char* hash_value = static_cast<char*>(malloc(count + 1));
    ZeroMemory(hash_value, count + 1);
    if (!CryptGetHashParam(*hHash, HP_HASHVAL, (BYTE*)hash_value, &count, 0))
    {
        cout << "!!!!!CryptGetHashParam error!!!!!!\n";
        return;
    }
    cout << "Hash value is recived "<< endl;
    
    CloseHandle(hFile);// close file
   
}

void create_ecp(HCRYPTHASH *hHash, DWORD *count)
{
    // Цифровая подпись хеш-значения

    //DWORD count = 0;
    
     if (!CryptSignHash(*hHash, 1, NULL, 0, NULL, count))
    {
        cout << "Error(CryptSignHash)1\n";
        return;
    }

    char* sign_hash = static_cast<char*>(malloc(*count + 1));
	ZeroMemory(sign_hash, *count + 1);

    if (!CryptSignHashW(*hHash, 1, NULL, 0, (BYTE*)sign_hash, count))
    {
        cout << "Error(CryptSignHash)2\n";
        return;
    }
    cout << "Signature created: \n";

    FILE* out;
    if (fopen_s(&out, "D:\\sign.txt", "w") != 0) { cout << "error open file for writing ecp\n"; };
    if (!fwrite(sign_hash, sizeof byte, *count, out))
    {
        cout << "!!couldn't write ecp to the file\n";
        return;

    }
    cout << "ECP was written to the file\n";
    fclose(out);
}

void check_ecp(HCRYPTHASH* hHash, HCRYPTKEY hPrivateKey, DWORD count)
{
  
    // проверка эцп
    char* sign_hash = static_cast<char*>(malloc(count + 1));

    FILE* sign_file;
    if (fopen_s(&sign_file, "D:\\sign.txt", "rb") != 0) { cout << "!!! couldn't open file fo reading ecp\n"; };


    if (!fread(sign_hash, sizeof byte, count, sign_file))
    {
        cout << "couldn't read ecp from file\n ";
        return;
        
    }
    cout << "ECP was read from file\n " << endl;;
    fclose(sign_file);

    if (CryptVerifySignatureW(*hHash, (BYTE*)sign_hash, count, hPrivateKey, NULL, 0))//здесь почему-то не работает
    {
        cout << "ECP varified!" << endl;
    }
    else
    {
        cout << "ECP NOT verivfied!" << endl;
       
    }
}

// открытие хранилища сертификатов
void open_cStore(HCRYPTPROV* hProv)
{
    HCERTSTORE hStore;
    PCCERT_CONTEXT hContext = NULL;
    LPTSTR pszName = new TCHAR[128];
    DWORD keySpec = 0;
    int i = 0; int certNum = 0;
    if (!(hStore = CertOpenSystemStoreA(NULL, "MY")))
    {
        cout << "!!!!err open store!!!\n"; cin.get(); return;
    }

    while (hContext = CertEnumCertificatesInStore(hStore, hContext))
    {
        if (!CertGetNameStringW(hContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, pszName, 128))
        {
            cout << "!!!!err get name!!!!\n"; cin.get(); return;
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
        cin.get(); return;
    }

    // импортируем публичный ключ

    if (CryptImportPublicKeyInfo(*hProv, MY_TYPE, &hContext->pCertInfo->SubjectPublicKeyInfo, &KeyPair.PublicKey))
    {
        cout << "import public key: " << KeyPair.PublicKey << endl;
    }
    else { cout << "err import public key\n"; }

    //извлечение из сертификата контекста приватного ключа

    if (!CryptAcquireCertificatePrivateKey(hContext, NULL, NULL, hProv, &keySpec, NULL))
    {
        cout << "!!!!error getting private context!!!!!!!!!!\n";
        cout << hProv << endl;

        return;
    }
    //извлечение закрытого ключа
    if (!CryptGetUserKey(*hProv, keySpec, &KeyPair.PrivateKey))
    {
        cout << "!!!!!err getting private key!!!!\n";

        return;
    }
    else { cout << "import privateKey: " << KeyPair.PrivateKey << endl; }
    return;
}

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

int main()
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTHASH newHash;
    DWORD count =0;
   
    initCryptProv(&hProv);// Получение контекста криптопровайдера
    open_cStore(&hProv);// извлечение сертификата
    doHash(&hProv,&hHash);//получение хэша 
    create_ecp(&hHash,&count);// подпись сообщения
    doHash(&hProv, &newHash);//получение хэша для проверки
    check_ecp(&newHash,KeyPair.PrivateKey, count);// проверка эцп
    CryptDestroyHash(hHash);
}
