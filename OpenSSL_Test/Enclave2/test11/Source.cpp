#include<stdio.h>
#include<tchar.h>
#include "sgx_urts.h"
#include "Enclave2_u.h"
#include <windows.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>

#define ENCLAVE_FILE _T("Enclave2.signed.dll")
#define MAX_BUF_LEN 10000
#define MAX_STRUCT_BUF 1000000
#define MAX_OUTENCLAVE_BUF_LEN 10000
#define MAX_LINE_BUF 10000

int
add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *tmp1 = BN_CTX_get(ctx);

	if (!BN_mod_mul(tmp1, a, b, n2, ctx))
		goto end;

	BN_copy(result, tmp1);

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
		//		fprintf(stderr, "add: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}


void emptyChar(char* tmp)
{
	int k = 0;
	while (tmp[k] != -52)
	{
		tmp[k] = -52;
		k += 1;
	}
}
using namespace std;
// get buffer from the file----------------------------------
char * getBuffer(std::string path, int * buffer_length)
{
	//char buffer[MAX_LINE_BUF];
	std::ifstream getFile;
	getFile.open(path, std::ios::binary);
	getFile.seekg(0, ios::end);
	*buffer_length = getFile.tellg();
	getFile.seekg(0, ios::beg);
	char *tmp = new char[*buffer_length];
	getFile.read(tmp, *buffer_length);
	return tmp;
}

/*	int index = 0;
	int max_bits = 1000;
	int max_byte = max_bits / 8;
	while (!getFile.eof())
	{
		int num_level;
		getFile.read((char*)&num_level, 4);
		std::vector<char *> tmp_structBuffer;
		for (int i = 0; i < num_level; i++)
		{
			int str_len;
			getFile.read((char*)&str_len, 4);
			while (1)
			{
				int tmp_len = min(str_len, max_byte);
				char * tmp = new char[tmp_len];
				getFile.read(tmp, tmp_len);
				tmp_structBuffer.push_back(tmp);
				str_len -= max_byte;
				if (str_len <= 0) { break; }
			}
		}*/
		/*int i = 0;
		getFile.getline(buffer, MAX_LINE_BUF, '\n');
		while (buffer[i] != NULL)
		{
			structBuffer[index] = buffer[i];
			i++;
			index++;
		}
		structBuffer[index] = ';';
		index += 1;*/
	//}

void getCountBuffer(char* publicKey, vector<vector<BIGNUM *>> countBuf, std::string path,std::vector<int> pV)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *random = BN_CTX_get(ctx);

	std::ifstream getFile;
	getFile.open(path, std::ios::binary);
	getFile.seekg(0, ios::end);
	int buffer_length = getFile.tellg();
	getFile.seekg(0, ios::beg);
	char *tmp = new char[buffer_length];
	getFile.read(tmp, buffer_length);
#define key_length_bytes 256	
	int max_bits = 1000;
	int max_byte = max_bits / 8;
	char *pos = tmp;
	int num_level = *((int*)pos);
	pos += 4;
	for (int i = 0; i < num_level-1; i++)
	{
		vector<BIGNUM *> temp_buf;
		int str_len = *((int*)pos);
		pos += 4;
		for (int j = 0; j < str_len; j++)
		{
			BN_bin2bn((const unsigned char*)pos + j*(key_length_bytes + 1), key_length_bytes, random);
			temp_buf.push_back(random);
			pos += (key_length_bytes + 1);
		}
		countBuf.push_back(temp_buf);
	}


	BIGNUM *a = countBuf[pV[0]][pV[1]];

	for (int i = 2; i < pV.size(); i+=2)
	{
		//BN_CTX *ctx = BN_CTX_new();
		BIGNUM *result = BN_CTX_get(ctx);

		BIGNUM *b = countBuf[pV[0]][i];
		BIGNUM *n2 = BN_CTX_get(ctx);
		char temp1[MAX_OUTENCLAVE_BUF_LEN];
		int count = 0;
		int pre = 0;
		for (int i = 0; i < strlen(publicKey); i++)
		{
			if (publicKey[i] == ';')
			{
				count += 1;
				i += 1;
			}
			if (count == 1)
			{
				temp1[pre] = publicKey[i];
				pre += 1;
			}
			if (count == 2)
				break;
		}
		BN_dec2bn(&n2, temp1);

		add(result, a, b, n2, ctx);
		a = result;
	}
		


	/*std::fstream getFile;
	getFile.open(path, std::ios::in);
	int bufIndex = 0;
	int lineIndex = 1;
	int pVIndex = 0;
	while (!getFile.eof())
	{
		char buffer[MAX_OUTENCLAVE_BUF_LEN];
		int i = 0;
		getFile.getline(buffer, MAX_OUTENCLAVE_BUF_LEN, '\n');
		while (buffer[i] != NULL && lineIndex==pV[pVIndex])
		{
			buf[bufIndex] = buffer[i];
			i++;
			bufIndex++;
		}
		if(lineIndex == pV[pVIndex])
			pVIndex += 2;
		if (pVIndex >= pV.size())
			break;
		lineIndex += 1;
	}*/
}

//build count struct---------------------------------------------------
void buildCountStruct(char* buf, std::vector<std::string>& DV)
{
//	DV.push_back(" ");
	int bufIndex = 0;
	int bufPreIndex = 0;

	while (buf[bufIndex] != -52)
	{
		if (buf[bufIndex] == '.')
		{
			char temp[MAX_OUTENCLAVE_BUF_LEN];
			for (int i = bufPreIndex; i < bufIndex; i++)
				temp[i - bufPreIndex] = buf[i];
			std::string tempS = temp;
			tempS = tempS.substr(0, bufIndex - bufPreIndex);
			DV.push_back(tempS);
			bufPreIndex = bufIndex + 1;
		}
		bufIndex++;
	}
}

//return a position vector ----------------------------
void positionVector(std::vector<int>& pV, char * positionBuffer)
{
	int index = 0;
	int flag = 1;
	int total = 0;
	while (positionBuffer[index] != ';')
	{
		if (positionBuffer[index] != ' ')
		{
			total = (positionBuffer[index] - 48)+total*flag;
			flag = 10;
		}
		else
		{
			pV.push_back(total);
			total = 0;
			flag = 1;
		}
		if (positionBuffer[index + 1] == ';')
			pV.push_back(total);
		index += 1;
	}
}

// return value vector------------------------------------------------------------------
std::vector<std::string> findValue(std::vector<int> pV, std::vector<std::string> DV)
{

	std::vector<std::string> store;
	int j = 0;
	int count = 0;

	for (int i = 1; i < pV.size(); i+=2)
	{
		int pre = 0, cur = 0;
		while (count < pV[i])
		{
			if (DV[j][cur] == ' ' || DV[j][cur] == ';')
				count += 1;
			cur += 1;
		}
		pre = cur;
		while (DV[j][cur] != ' ' && DV[j][cur] != ';')
			cur += 1;
		std::string tmp;
		tmp = DV[j].substr(pre, cur - pre );
		store.push_back(tmp);
		j += 1;
		count += 1;
	}
	return store;
}

// write key to the file------------------------------------------------------------
void writeKeyToFile(char* tempS)
{
	std::ofstream write1;
	write1.open("C:\\Users\\user\\Desktop\\GenerateFile\\publicKey.txt", std::ios::trunc);
	write1.write(tempS, strlen(tempS));
	write1.close();
}


// HME addition and return char*---------------------------
char* addtion(std::vector<std::string> res,char* publicKey)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *finalTotal = BN_CTX_get(ctx);
	BIGNUM *total = BN_CTX_get(ctx);
	BIGNUM *temp = BN_CTX_get(ctx);
	BIGNUM *n2 = BN_CTX_get(ctx);
	char temp1[MAX_OUTENCLAVE_BUF_LEN];

//	emptyChar(temp1);
	for (int j = 0; j < res[0].length(); j++)
		temp1[j] = res[0][j];
	BN_dec2bn(&total, temp1);
	
	int count = 0;
	int pre = 0;
	for (int i = 0; i < strlen(publicKey); i++)
	{
		if (publicKey[i] == ';')
		{
			count += 1;
			i += 1;
		}
		if (count == 1)
		{
			temp1[pre] = publicKey[i];
			pre += 1;
		}
		if (count == 2)
			break;
	}
	BN_dec2bn(&n2, temp1);

	for (int i = 1; i < res.size(); i++)
	{
//		emptyChar(temp1);
		for (int j = 0; j < res[i].length(); j++)
			temp1[j] = res[i][j];
		BN_dec2bn(&temp, temp1);
		add(finalTotal, total, temp, n2, ctx);
		total = finalTotal;
	}

//	emptyChar(temp1);
	return BN_bn2dec(finalTotal);
}

int main()
{
// initailizing the timer----------------------------------------------------------
	LARGE_INTEGER f;
	QueryPerformanceFrequency(&f);

	double dFreq, duration;
	dFreq = (double)f.QuadPart;

	LARGE_INTEGER start, end;
//////////////////////////////////////////////////////////////////////////////////////

	std::string path="";
// This part used to create an Enclave-------------------------------------------------	
	sgx_enclave_id_t eid;
	sgx_status_t   ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int update = 0;
	ret=sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &update, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP: error %#x",ret);
		return -1;
	}
///////////////////////////////////////////////////////////////////////////////////////

//generate the public key--------------------------------------------------------------
	char publicKey[MAX_BUF_LEN];
	generateKey(eid,publicKey,MAX_BUF_LEN);
	writeKeyToFile(publicKey);
///////////////////////////////////////////////////////////////////////////////////////



// This part used to send Tree structure to Enclave and store it in Enclave------------
	//char *structBuffer = new char[MAX_STRUCT_BUF];
	std::ifstream getFile;
	path = "C:\\Users\\user\\Desktop\\GenerateFile\\struct.bin";
	getFile.open(path, std::ios::binary);
	while (!getFile)
	{
		getFile.close();
		Sleep(5000);
		getFile.open(path, std::ios::binary);
	}
	getFile.close();
	QueryPerformanceCounter(&start);
	int buffer_length;
	char *structBuffer =getBuffer(path, &buffer_length);// return structBuffer by reference
	
	sendStruct(eid, structBuffer, buffer_length);
///////////////////////////////////////////////////////////////////////////////////////
	QueryPerformanceCounter(&end);
	duration = (double)(end.QuadPart - start.QuadPart) / dFreq;
	printf(" Time of store the tree structure in enclave: %f\n", duration);
	


	QueryPerformanceCounter(&start);
// This part used to send query to Enclave and get position ---------------------------
	char queryBuffer[MAX_BUF_LEN];
	getFile.open("C:\\Users\\user\\Desktop\\query\\query.txt", std::ios::in);
	getFile.getline(queryBuffer, MAX_OUTENCLAVE_BUF_LEN, '\n');
	Query(eid, queryBuffer, MAX_BUF_LEN);// return queryBuffer by reference
	std::vector<int> pV;
	positionVector(pV, queryBuffer);// return pV by reference
	getFile.close();
	QueryPerformanceCounter(&end);
	duration = (double)(end.QuadPart - start.QuadPart) / dFreq;
	printf(" Time of query: %f\n", duration);





	QueryPerformanceCounter(&start);
// This part used to get result back ----------------------------------
	path = "C:\\Users\\user\\Desktop\\GenerateFile\\count.bin";
	vector<vector<BIGNUM *>> countBuffer;
	getCountBuffer(publicKey, countBuffer, path,pV);// return countBuffer by reference
	
	//std::vector<std::string> DV;
	//buildCountStruct(countBuffer,DV);// return DV by reference
	//std::vector<std::string> res=findValue(pV,DV);	// find position

//This part is used to addtion and send the result to enclave---------------
	//char* test=addtion(res,publicKey);
//	enclaveAddition(eid,test,MAX_BUF_LEN);
//////////////////////////////////////////////////////////////////////////////////////
	QueryPerformanceCounter(&end);
	duration = (double)(end.QuadPart - start.QuadPart) / dFreq;
	printf(" Time of HME addition: %f\n", duration);

	//delete structBuffer;

	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	system("pause");
	return 0;
}