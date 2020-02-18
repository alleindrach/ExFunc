#include "windows.h"
#include <io.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "minwindef.h"
#include <cassert> 
#include "openssl/md5.h"    
#include "openssl/sha.h"    
#include "openssl/des.h"    
#include "openssl/rsa.h"    
#include "openssl/pem.h"    
#define KEY_LENGTH  2048               // 密钥长度  

#define PASS "" //口令
using namespace std;
#define pubkeyFilename  "c:\\exfunc\\pubkey.pem"
#define prikeyFilename  "c:\\exfunc\\prikey.pem"
#define licenseFilename "c:\\exfunc\\license"
#define tokenFilename  "c:\\exfunc\\token"
#define logFilename  "c:\\exfunc\\log"
char * Base64Encode(const char * input, int length, bool with_new_line);

char * Base64Decode(const char * input, int length, bool with_new_line);
// ---- md5摘要哈希 ---- //    
void md5(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr);
// ---- sha256摘要哈希 ---- //    
void sha256(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr);

// ---- des对称加解密 ---- //    
// 加密 ecb模式    
std::string des_encrypt(const std::string &clearText, const std::string &key);
// 解密 ecb模式    
std::string des_decrypt(const std::string &cipherText, const std::string &key);
// ---- rsa非对称加解密 ---- //    


// 命令行方法生成公私钥对（begin public key/ begin private key）  
// 找到openssl命令行工具，运行以下  
// openssl genrsa -out prikey.pem 1024   
// openssl rsa - in privkey.pem - pubout - out pubkey.pem  

// 公钥加密    
std::string rsa_pub_encrypt(const std::string &cipherText, char * priKeyFile, std::string& logfile);
// 公钥解密    
std::string rsa_pub_decrypt(const std::string &cipherText, char * priKeyFile, std::string& logfile);
// 私钥解密    
std::string rsa_pri_decrypt(const std::string &cipherText, char * priKeyFile, std::string& logfile);
// 私钥加密
std::string rsa_pri_encrypt(const std::string &cipherText, char * priKeyFile, std::string& logfile);

void format(std::string & str, const char *pszFmt, ...);
string  GetCPUID(std::string&  venderId, std::string& cpuid1, std::string& cpuid2);

//生成的dll及相关依赖dll请拷贝到通达信安装目录的T0002/dlls/下面,再在公式管理器进行绑定
void out(std::string filename, std::string  txt);
std::string readAll(std::string filename);
std::string  token();

bool genToken(std::string filename, std::string logfile);
bool genLicnese(std::string tf, std::string lf, std::string logfile);
bool verifyLicense(std::string filename, std::string logfile);