#include "stdafx.h"
#include "Funcs.h"  
#include <assert.h>
using namespace std;

char * Base64Encode(const char * input, int length, bool with_new_line)
{
	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	if (!with_new_line) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char * buff = (char *)malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;

	BIO_free_all(b64);

	return buff;
}

char * Base64Decode(const char * input, int length, bool with_new_line)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;
	char * buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	if (!with_new_line) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new_mem_buf((char *)input, length);
	bmem = BIO_push(b64, bmem);
	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}
// ---- md5摘要哈希 ---- //    
void md5(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr)
{
	// 调用md5哈希    
	unsigned char mdStr[33] = { 0 };
	MD5((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);

	// 哈希后的字符串    
	encodedStr = std::string((const char *)mdStr);
	// 哈希后的十六进制串 32字节    
	char buf[65] = { 0 };
	char tmp[3] = { 0 };
	for (int i = 0; i < 32; i++)
	{
		sprintf(tmp, "%02x", mdStr[i]);
		strcat(buf, tmp);
	}
	buf[32] = '\0'; // 后面都是0，从32字节截断    
	encodedHexStr = std::string(buf);
}

// ---- sha256摘要哈希 ---- //    
void sha256(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr)
{
	// 调用sha256哈希    
	unsigned char mdStr[33] = { 0 };
	SHA256((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);

	// 哈希后的字符串    
	encodedStr = std::string((const char *)mdStr);
	// 哈希后的十六进制串 32字节    
	char buf[65] = { 0 };
	char tmp[3] = { 0 };
	for (int i = 0; i < 32; i++)
	{
		sprintf(tmp, "%02x", mdStr[i]);
		strcat(buf, tmp);
	}
	buf[32] = '\0'; // 后面都是0，从32字节截断    
	encodedHexStr = std::string(buf);
}

// ---- des对称加解密 ---- //    
// 加密 ecb模式    
std::string des_encrypt(const std::string &clearText, const std::string &key)
{
	std::string cipherText; // 密文    

	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	// 构造补齐后的密钥    
	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	// 密钥置换    
	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	// 循环加密，每8字节一次    
	const_DES_cblock inputText;
	DES_cblock outputText;
	std::vector<unsigned char> vecCiphertext;
	unsigned char tmp[8];

	for (int i = 0; i < clearText.length() / 8; i++)
	{
		memcpy(inputText, clearText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCiphertext.push_back(tmp[j]);
	}

	if (clearText.length() % 8 != 0)
	{
		int tmp1 = clearText.length() / 8 * 8;
		int tmp2 = clearText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, clearText.c_str() + tmp1, tmp2);
		// 加密函数    
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCiphertext.push_back(tmp[j]);
	}

	cipherText.clear();
	cipherText.assign(vecCiphertext.begin(), vecCiphertext.end());

	return cipherText;
}

// 解密 ecb模式    
std::string des_decrypt(const std::string &cipherText, const std::string &key)
{
	std::string clearText; // 明文    

	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	const_DES_cblock inputText;
	DES_cblock outputText;
	std::vector<unsigned char> vecCleartext;
	unsigned char tmp[8];

	for (int i = 0; i < cipherText.length() / 8; i++)
	{
		memcpy(inputText, cipherText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCleartext.push_back(tmp[j]);
	}

	if (cipherText.length() % 8 != 0)
	{
		int tmp1 = cipherText.length() / 8 * 8;
		int tmp2 = cipherText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, cipherText.c_str() + tmp1, tmp2);
		// 解密函数    
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; j++)
			vecCleartext.push_back(tmp[j]);
	}

	clearText.clear();
	clearText.assign(vecCleartext.begin(), vecCleartext.end());

	return clearText;
}

// 命令行方法生成公私钥对（begin public key/ begin private key）  
// 找到openssl命令行工具，运行以下  
// openssl genrsa -out prikey.pem 1024   
// openssl rsa - in privkey.pem - pubout - out pubkey.pem  

// 公钥加密    
std::string rsa_pub_encrypt(const std::string &cipherText, char * pubKeyFile, string& logfile)
{
	std::string strRet;
	RSA *publicRsa = NULL;
	BIO *keybio;
	keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, pubKeyFile);
	try {
		if ((publicRsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL)) == NULL)
		{
			out(logfile, "PEM_read_RSA_PUBKEY error\n");

		}
		else
		{
			int rsa_len = RSA_size(publicRsa);
			unsigned char *encryptedText = (unsigned char *)malloc(rsa_len);
			memset(encryptedText, 0, rsa_len);

			int ret = RSA_public_encrypt(cipherText.length(), (const unsigned char *)cipherText.c_str(), encryptedText, publicRsa, RSA_PKCS1_PADDING);

			if (ret < 0)
				out(logfile, "RSA_public_encrypt error\n");
			else {
				strRet = string((char*)encryptedText, ret);
			}
		}
	
		
	}
	catch (exception e) {
		out(logfile, e.what());
	}
	

	// 释放内存  

	RSA_free(publicRsa);
	BIO_free_all(keybio);
	return strRet;
}

// 公钥解密    
std::string rsa_pub_decrypt(const std::string &cipherText, char * pubKeyFile, string& logfile)
{
	std::string strRet;
	RSA *publicRsa = NULL;
	BIO *keybio;
	keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, pubKeyFile);

	if ((publicRsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL)) == NULL)
	{
		out(logfile,"PEM_read_RSA_PUBKEY error\n");
		
	}
	else
	{
		int rsa_len = RSA_size(publicRsa);
		unsigned char *decryptedText = (unsigned char *)malloc(rsa_len);
		memset(decryptedText, 0, rsa_len);
		int len = cipherText.length();
		const unsigned char * data = (const unsigned char *)cipherText.c_str();
		int ret = RSA_public_decrypt(rsa_len, data, decryptedText, publicRsa, RSA_PKCS1_PADDING);

		if (ret < 0)
			out(logfile, "RSA_public_decrypt error\n");
		else {
			strRet = string((char*)decryptedText, ret);
		}
	}
	// 释放内存  
	RSA_free(publicRsa);
	BIO_free_all(keybio);
	return strRet;
}

// 私钥解密    
std::string rsa_pri_decrypt(const std::string &cipherText, char * priKeyFile,string& logfile)
{
	std::string strRet;
	RSA *privateRsa = NULL;
	BIO *keybio;
	keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, priKeyFile);
	if ((privateRsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL)) == NULL)
	{
		out(logfile,"PEM_read_RSAPrivateKey error\n");
		
	}
	else {

		int rsa_len = RSA_size(privateRsa);
		unsigned char *decryptedText = (unsigned char *)malloc(rsa_len);
		memset(decryptedText, 0, rsa_len);

		int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char *)cipherText.c_str(), decryptedText, privateRsa, RSA_PKCS1_PADDING);

		if (ret < 0)
			out(logfile, "RSA_private_decrypt error\n");
		else {
			strRet = string((char*)decryptedText, ret);
		}
	}
	
	// 释放内存  
	
	RSA_free(privateRsa);
	BIO_free_all(keybio);

	return strRet;
}

// 私钥加密
std::string rsa_pri_encrypt(const std::string &cipherText, char *  priKeyFile, string& logfile)
{
	std::string strRet;
	RSA *privateRsa = NULL;
	BIO *keybio;
	keybio = BIO_new(BIO_s_file());
	BIO_read_filename(keybio, priKeyFile);


	if ((privateRsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL)) == NULL)
	{
		out(logfile,"PEM_read_RSAPrivateKey error\n");
		return string();
	}
	else {
		int rsa_len = RSA_size(privateRsa);
		unsigned char *encryptedText = (unsigned char *)malloc(rsa_len);
		memset(encryptedText, 0, rsa_len);

		int ret = RSA_private_encrypt(cipherText.length(), (const unsigned char *)cipherText.c_str(), encryptedText, privateRsa, RSA_PKCS1_PADDING);

		if (ret < 0)
			out(logfile, "RSA_private_decrypt error\n");
		else {
			strRet = string((char*)encryptedText, ret);
		}
	}
	

	
	// 释放内存  

	RSA_free(privateRsa);
	BIO_free_all(keybio);
	return strRet;
}

void format(string & str, const char *pszFmt, ...)
{

	va_list args;
	va_start(args, pszFmt);
	{
		int nLength = _vscprintf(pszFmt, args);
		nLength += 1;  //上面返回的长度是包含\0，这里加上
		std::vector<char> vectorChars(nLength);
		_vsnprintf(vectorChars.data(), nLength, pszFmt, args);
		str.assign(vectorChars.data());
	}
	va_end(args);
	return;
}

string  GetCPUID(string&  venderId, string& cpuid1, string& cpuid2)
{

	unsigned long s1, s2;
	unsigned char vendor_id[] = "------------";

	__asm
	{
		xor eax, eax      //eax=0:取Vendor信息
		cpuid    //取cpu id指令，可在Ring3级使用
		mov dword ptr vendor_id, ebx
		mov dword ptr vendor_id[+4], edx
		mov dword ptr vendor_id[+8], ecx
	}

	format(venderId, "%s-", vendor_id);
	__asm
	{
		mov eax, 01h   //eax=1:取CPU序列号
		xor edx, edx
		cpuid
		mov s1, edx
		mov s2, eax
	}
	format(cpuid1, "%08X%08X", s1, s2);
	__asm
	{
		mov eax, 03h
		xor ecx, ecx
		xor edx, edx
		cpuid
		mov s1, edx
		mov s2, ecx
	}
	format(cpuid2, "%08X%08X", s1, s2);
	string id = cpuid1 + cpuid2;
	return id;
}
void out(string filename, string txt)
{
	fstream f;
	f.open(filename, ios::out);
	if (f) {
		f << txt;
	}
	f.close();
}
void out(const char *  filename, const char  * txt,int len)
{

	FILE * fp = fopen(filename, "wb");

	int wl=fwrite(txt, sizeof(char), len, fp);       // read the whole file into the buffer
	fclose(fp);
	
	return ;
}
string readAll(const char *  filename) {

	FILE * fp=fopen(filename,"rb");
	fseek(fp, 0L, SEEK_END);
	
	int length;
	
	length =ftell(fp);           // report location (this is the length)
	fseek(fp, 0L, SEEK_SET);

	char * buffer = new char[length];    // allocate memory for a buffer of appropriate dimension
	fread(buffer,sizeof(char), length,fp);       // read the whole file into the buffer
	fclose(fp);
	string result(buffer,length);
	delete buffer;
	return result;
}

string  token() {
	char strBuffer[256] = { 0 };
	memset(strBuffer, 0, 255);
	DWORD dwSize = 256;
	GetUserName(strBuffer, &dwSize);
	string userName(strBuffer);
	string venderId, cpuid1, cpuid2;
	string cpuid = GetCPUID(venderId, cpuid1, cpuid2);
	cout << "USERID:" << userName << ",CPU:" << cpuid;
	std::string srcText = cpuid + userName;

	std::string encryptText;
	std::string encryptHexText;
	std::string decryptText;

	md5(srcText, encryptText, encryptHexText);
	cout << "TOKEN:" << encryptHexText;
	return encryptHexText;
}
bool genToken(string filename, string logfile) {
	string strToken = token();

	try {
		string encryptText = rsa_pub_encrypt(strToken,pubkeyFilename, logfile);
		string decrypt = rsa_pri_decrypt(encryptText,prikeyFilename, logfile);
		out(filename.c_str(), (const char *)encryptText.c_str(), encryptText.length());
		assert(decrypt.compare(strToken) == 0);
		cout << "decrypt:" << decrypt;
	}
	catch (exception e)
	{
		out(logfile, e.what());
		return false;
	}

	return true;
}
bool genLicnese(string tf, string lf, string logfile) {

	string encryptText = readAll(tf.c_str());
	if (encryptText.empty()) {
		out(logfile, "Token文件错误");
	}
	try {

		string decryptText = rsa_pri_decrypt(encryptText, prikeyFilename,logfile);
		std::cout << "私钥解密字符： " << decryptText << std::endl;
		string encryptText = rsa_pri_encrypt(decryptText, prikeyFilename,logfile);
		string decryptText2 = rsa_pub_decrypt(encryptText, pubkeyFilename, logfile);
		out(lf.c_str(), (const char *)encryptText.c_str(), encryptText.length());

	}
	catch (exception e) {
		out(logfile, e.what());
		return false;
	}
	return true;

}
bool verifyLicense(string filename, string logfile) {
	string strToken;
	string license;
	try {
		strToken = token();
	}
	catch (exception e) {
		out(logfile, e.what());
	}
	try {
		license = readAll(filename.c_str());
		if (license.empty()) {
			out(logfile, "License文件错误");
		}
	}
	catch (exception e) {
		out(logfile, e.what());
	}
	
	try {

		string decryptedText = rsa_pub_decrypt(license, pubkeyFilename,logfile);
		if (decryptedText.compare(strToken) == 0) {
			return true;
		}
		else
		{
			return false;
		}
	}
	catch (exception e) {
		out(logfile, e.what());
		return false;
	}

}

