#include "Enclave2_t.h"

#include "sgx_trts.h"

#include <windows.h>
#include <string.h>
#include <vector>
#include "homomophic.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>
#include <queue>
#include <stdlib.h> 
#include <stdio.h> 
#include <string>
#include <sstream>
#include <unordered_map>

// initial some feature------------------------------------------------------------------
std::vector<std::vector<std::string>> DataVector;
paillierKeys keys;
BN_CTX *ctx = BN_CTX_new();
struct TreeNode
{
	std::string val;
	int count = 0;
	TreeNode* child;
	std::vector<TreeNode*> sibling;
	TreeNode(std::string x) : val(x), child(NULL) {}
};
TreeNode* root = new TreeNode(" ");
////////////////////////////////////////////////////////////////////////////////////////////

static int BN_lcm(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	int ret = 0;
	BN_CTX_start(ctx);

	BIGNUM *tmp = BN_CTX_get(ctx);
	BIGNUM *gcd = BN_CTX_get(ctx);

	if (!BN_gcd(gcd, a, b, ctx))
		goto end;
	if (!BN_div(tmp, NULL, a, gcd, ctx))
		goto end;
	if (!BN_mul(r, b, tmp, ctx))
		goto end;

	ret = 1;
end:
	if (ret != 1)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Error calculating lcm: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}
// For key generation
static int L(BIGNUM *res, const BIGNUM *u, const BIGNUM *n, BN_CTX *ctx)
{
	int ret = 1;

	BIGNUM *u_cp = BN_dup(u);
	if (!BN_sub_word(u_cp, 1))
		goto end;
	if (!BN_div(res, NULL, u_cp, n, ctx))
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Error calculating L: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_free(u_cp);
	return ret;
}

int generateRandomKeys(paillierKeys *keys, int *key_len, BN_CTX *ctx)
{
	int ret = 1, final_key_l = 0;
	BIGNUM *p, *q, *tmp, *n, *n2, *g, *lamda, *mu;

	if (key_len != NULL && *key_len == 0)
	{
		*key_len = DEFAULT_KEY_LEN;
		final_key_l = *key_len;
	}
	else if (key_len != NULL)
	{
		final_key_l = *key_len;
	}
	else
	{
		final_key_l = DEFAULT_KEY_LEN;
	}

	if (final_key_l < 32)
	{
//		fprintf(stderr, "Key lenght too short. Minimum lenght 32 bits");
		goto end;
	}

	BN_CTX_start(ctx);

	// Temp BIGNUMs
	p = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);
	tmp = BN_CTX_get(ctx);

	// Part of the keys BIGNUMs
	n = BN_new();
	n2 = BN_new();
	g = BN_new();
	lamda = BN_new();
	mu = BN_new();

	// 1. Choose two large prime numbers
	// This numbers have to hold gcd(pq, (p-1)(q-1)) = 1
	unsigned char buffer;
	do
	{

		if (!RAND_bytes(&buffer, sizeof(buffer)))
			goto end;
		//srandom((int)buffer);

		if (!BN_generate_prime_ex(p, final_key_l / 2, 0, NULL, NULL, NULL))
			goto end;
		if (!BN_generate_prime_ex(q, final_key_l / 2, 0, NULL, NULL, NULL))
			goto end;

		// 2. Compute n = pq
		if (!BN_mul(n, p, q, ctx))
			goto end;

		// Test if primes are ok
		if (!BN_sub_word(p, 1))
			goto end;
		if (!BN_sub_word(q, 1))
			goto end;
		if (!BN_mul(tmp, p, q, ctx))
			goto end;

	} while (BN_cmp(p, q) == 0 || BN_gcd(tmp, tmp, n, ctx) != 1);

	// and lamda = lcm(p-1,q-1)
	if (!BN_lcm(lamda, p, q, ctx))
		goto end;

	if (!BN_mul(n2, n, n, ctx))
		goto end;
	do
	{
		// 3. Select a random integer g moz n2
		do
		{
			if (!BN_rand_range(g, n2))
				goto end;
		} while (BN_is_zero(g));

		// 4. Ensure n divides the order of g
		if (!BN_mod_exp(tmp, g, lamda, n2, ctx))
			goto end;
		if (L(tmp, tmp, n, ctx) != 0)
			goto end;

		BN_mod_inverse(mu, tmp, n, ctx);
	} while (mu == NULL);

	keys->pub.n = n;
	keys->pub.n2 = n2;
	keys->pub.g = g;

	keys->priv.n = BN_dup(n);
	keys->priv.n2 = BN_dup(n2);
	keys->priv.lamda = lamda;
	keys->priv.mu = mu;

	keys->n = BN_dup(n);
	keys->n2 = BN_dup(n2);

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Error generating keys: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int freeKeys(paillierKeys *keys)
{
	if (keys->pub.n)
		BN_free(keys->pub.n);
	if (keys->pub.g)
		BN_free(keys->pub.g);
	if (keys->pub.n2)
		BN_free(keys->pub.n2);

	if (keys->priv.lamda)
		BN_free(keys->priv.lamda);
	if (keys->priv.mu)
		BN_free(keys->priv.mu);
	if (keys->priv.n)
		BN_free(keys->priv.n);
	if (keys->priv.n2)
		BN_free(keys->priv.n2);

	return 0;
}

int encryptll(BIGNUM *c, const long long plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *m = BN_CTX_get(ctx);

	if (!BN_set_word(m, plain))
		goto end;
	if (encrypt(c, m, key, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Can't encrypt %lld: %s", plain, ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int encrypt(BIGNUM *c, const BIGNUM *m, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *r = BN_CTX_get(ctx);
	BIGNUM *tmp1 = BN_CTX_get(ctx);
	BIGNUM *tmp2 = BN_CTX_get(ctx);

	// 1. Let m be the message to be encrypted where m E Zn
	if (BN_cmp(m, key->n) >= 0)
	{
//		fprintf(stderr, "Message not in Zn");
		goto end;
	}

	// 2. Select random r where r E Zn*
	do
	{
		if (!BN_rand(r, DEFAULT_KEY_LEN, 0, 0))
			goto end;
	} while (BN_is_zero(r));

	if (!BN_mod(r, r, key->n, ctx))
		goto end;

	// 3. Compute ciperthext as c = g^m*r^n mod n^2
	if (!BN_mod_exp(tmp1, key->g, m, key->n2, ctx))
		goto end;
	if (!BN_mod_exp(tmp2, r, key->n, key->n2, ctx))
		goto end;

	if (!BN_mod_mul(c, tmp1, tmp2, key->n2, ctx))
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Error ecnrypting: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);

	return ret;
}

int decrypt(BIGNUM *plain, const BIGNUM *c, const privKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *tmp = BN_CTX_get(ctx);

	// 1. Let c be the ciphertext to decrypt, where c E Zn2
	if (!BN_cmp(c, key->n2) == 1)
	{
//		fprintf(stderr, "Message provided not in Zn2");
		goto end;
	}

	// 2. Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
	if (!BN_mod_exp(tmp, c, key->lamda, key->n2, ctx))
		goto end;
	if (L(tmp, tmp, key->n, ctx) != 0)
		goto end;
	if (!BN_mod_mul(plain, tmp, key->mu, key->n, ctx))
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Can't decrypt: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}
int decryptll(long long *plain, const BIGNUM *c, const privKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);
	BIGNUM *plain_BN = BN_CTX_get(ctx);

	if (decrypt(plain_BN, c, key, ctx) != 0)
		goto end;

	*plain = BN_get_word(plain_BN);
	if (*plain == 0xffffffffL)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "Can't decrypt: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int
sub(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx)
{
	int ret = 0;
	BN_CTX_start(ctx);

	BIGNUM *b_inv = BN_CTX_get(ctx);

	if (!BN_mod_inverse(b_inv, b, n2, ctx))
		goto end;

	if (!BN_mod_mul(result, a, b_inv, n2, ctx))
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "sub: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int
subEncPlainll(BIGNUM *result, const BIGNUM *enc, const long long plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *plain_enc = BN_CTX_get(ctx);

	if (encryptll(plain_enc, plain, key, ctx) != 0)
		goto end;

	if (sub(result, enc, plain_enc, key->n2, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "subEncPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int
subEncPlain(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *plain_enc = BN_CTX_get(ctx);

	if (encrypt(plain_enc, plain, key, ctx) != 0)
		goto end;

	if (sub(result, enc, plain_enc, key->n2, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "subEncPlain: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int
subllPlainEnc(BIGNUM *result, const long long plain, const BIGNUM *enc, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *plain_enc = BN_CTX_get(ctx);

	if (encryptll(plain_enc, plain, key, ctx) != 0)
		goto end;

	if (sub(result, plain_enc, enc, key->n2, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "subllPlainEnc: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int
subPlainEnc(BIGNUM *result, const BIGNUM *plain, const BIGNUM *enc, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *plain_enc = BN_CTX_get(ctx);

	if (encrypt(plain_enc, plain, key, ctx) != 0)
		goto end;

	if (sub(result, plain_enc, enc, key->n2, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "subPlainEnc: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}
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

int
addEncPlainll(BIGNUM *result, const BIGNUM *enc, const long long plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *plain_enc = BN_CTX_get(ctx);

	if (encryptll(plain_enc, plain, key, ctx) != 0)
		goto end;

	if (add(result, enc, plain_enc, key->n2, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "addEncPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int
addEncPlain(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;
	BN_CTX_start(ctx);

	BIGNUM *plain_enc = BN_CTX_get(ctx);

	if (encrypt(plain_enc, plain, key, ctx) != 0)
		goto end;

	if (add(result, enc, plain_enc, key->n2, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "addEncPlain: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	BN_CTX_end(ctx);
	return ret;
}

int mulPlainll(BIGNUM *result, const BIGNUM *a, const long long plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;

	BN_CTX_start(ctx);
	BIGNUM *r = BN_CTX_get(ctx);

	if (!BN_set_word(r, plain))
		goto end;

	if (mulPlain(result, a, r, key, ctx) != 0)
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "mulPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
	}
	BN_CTX_end(ctx);
	return ret;
}

int mulPlain(BIGNUM *result, const BIGNUM *a, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx)
{
	int ret = 1;

	if (!BN_mod_exp(result, a, plain, key->n2, ctx))
		goto end;

	ret = 0;
end:
	if (ret)
	{
		ERR_load_crypto_strings();
//		fprintf(stderr, "mulPlain: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	return ret;
}

int dupKeys(paillierKeys *out, const paillierKeys *in)
{
	out->n2 = BN_dup(in->n2);
	out->n = BN_dup(in->n);

	out->pub.g = BN_dup(in->pub.g);
	out->pub.n = out->n;
	out->pub.n2 = out->n2;

	out->priv.lamda = BN_dup(in->priv.lamda);
	out->priv.mu = BN_dup(in->priv.mu);
	out->priv.n = out->n;
	out->priv.n2 = out->n2;

	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//for the tree ------------------------------------------------------------------------------------------------------------------------------------


void CreateTree(TreeNode* root, std::vector<std::string> test)
{
	std::queue<TreeNode*> treeQ;
	TreeNode *tmproot;

	treeQ.push(root);
	std::string value = "";
	for (int i = 0; i < test.size() - 1; i++)
	{
		int countIndex = 0;
		int j = 0;
		while(j < test[i].size())
		{
			tmproot = treeQ.front();
			if (test[i][j] == 'A' || test[i][j] == 'T' || test[i][j] == 'C' || test[i][j] == 'G')
			{
				std::string tmp = test[i].substr(j, 2);
				TreeNode * newNode = new TreeNode(tmp);
				newNode->count = countIndex;
				countIndex += 1;
				if (tmproot->child == nullptr)
					tmproot->child = newNode;
				else
					tmproot->sibling.push_back(newNode);
				treeQ.push(newNode);
				j += 2;
			}
			else if (test[i][j] == ';')
			{
				treeQ.pop();
				j += 1;
			}
			else
				j += 1;
		}
	}
}

void BFS(std::vector<std::string> queryVector,std::vector<int>& positionV)
{
	TreeNode * tmproot=root;
	std::queue<TreeNode*> treeQ;
	treeQ.push(tmproot);
	int lvl = 0;
	int i = 0;
	while( i < queryVector.size())
	{
		if (lvl < atoi(queryVector[i].c_str())-1)
		{
			int size = treeQ.size();
			for (int j = 0; j < size; j++)
			{
				tmproot = treeQ.front();
				treeQ.pop();
				if (tmproot->child != nullptr)
				{
					treeQ.push(tmproot->child);
					if (tmproot->sibling.size() > 0)
					{
						for (int k = 0; k < tmproot->sibling.size(); k++)
							treeQ.push(tmproot->sibling[k]);
					}
				}
			}
		}
		if (lvl == atoi(queryVector[i].c_str())-1)
		{
			int size = treeQ.size();
			for (int j = 0; j < size; j++)
			{
				tmproot = treeQ.front();
				treeQ.pop();
				if (tmproot->child != nullptr)
				{
					if(tmproot->child->val == queryVector[i + 1])
						treeQ.push(tmproot->child);
					if (tmproot->sibling.size() > 0)
					{
						for (int k = 0; k < tmproot->sibling.size(); k++)
							if (tmproot->sibling[k]->val==queryVector[i+1])
								treeQ.push(tmproot->sibling[k]);
					}
				}
			}
			i += 2;
		}
		lvl++;
	}

	positionV.push_back(lvl);
	while (!treeQ.empty())
	{
		tmproot = treeQ.front();
		positionV.push_back(tmproot->count);
		treeQ.pop();
	}

}

// for get structure operation -----------------------------------------------------------------------------------------------------------------------------------
std::string toWord(std::string tmp)
{
	tmp=tmp.substr(0,3);
	if (tmp == "101") {
		return "AA";
	}
	else if (tmp == "102") {
		return "AT";
	}
	else if (tmp == "103") {
		return "AG";
	}
	else if (tmp == "104") {
		return "AC";
	}
	else if (tmp == "105") {
		return "TT";
	}
	else if (tmp == "106") {
		return "GT";
	}
	else if (tmp == "107") {
		return "CT";
	}
	else if (tmp == "108") {
		return "GG";
	}
	else if (tmp == "109") {
		return "CG";
	}
	else if (tmp == "110") {
		return "CC";
	}
	else if (tmp == "111") {
		return " ";
	}
	else if (tmp == "112") {
		return ";";
	}
	else if (tmp == "113") {
		return ".";
	}
	return "";
}

#define myHashMap_AA 0x00
#define	myHashMap_AT 0x03
#define	myHashMap_AG 0x01
#define	myHashMap_AC 0x02
#define	myHashMap_TT 0x0F
#define	myHashMap_GT 0x07
#define	myHashMap_CT 0x0B
#define	myHashMap_GG 0x05
#define	myHashMap_CG 0x09
#define	myHashMap_CC 0x0A
#define	myHashMap_sp 0x08
#define	myHashMap_sc 0x0E
#define	myHashMap_pd 0x0C

void decode(char* buf)
{
	int index = 0;
	std::string decodeString = "";
	while (buf[index] !=NULL)
	{
		char tc[3];
		for (int i = 0; i < 3; i++)
		{
			tc[i] = buf[index];
			index += 1;
		}
		decodeString += toWord(tc);
	}
	for (int i = 0; i < decodeString.length(); i++)
		buf[i] = decodeString[i];
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

#define min(a, b) ((a)<(b)?(a):(b))
//get struct buf--------------------------------------
void sendStruct(char *buf, size_t lenOfString)
{
	long long decrypted = 0;
	BIGNUM *encrypted_random = BN_CTX_get(ctx);
	BIGNUM *decrypted_random = BN_CTX_get(ctx);
	
	int max_bits = 1000;
	int max_byte = max_bits / 8;
	char *pos = buf;
	int num_level = *((int*)pos);
	pos += 4;
	std::vector<unsigned char *> structBuffer;
	int *structBuffer_length = new int[num_level];
	for (int i = 0; i < num_level; i++)
	{
		int str_len = *((int*)pos);
		pos += 4;
		unsigned char *decrypt_text = (unsigned char *)malloc(str_len);
		for(int k = 0; k < ((str_len-1)/max_byte + 1); k++)
		{
			int tmp_len = *((int*)pos);
			pos += 4;
			char * tmp = new char[tmp_len];
			memcpy(tmp, pos, tmp_len);
			pos += tmp_len;

			BN_bin2bn((const unsigned char*)tmp, tmp_len, encrypted_random);
			decrypt(decrypted_random, encrypted_random, &keys.priv, ctx);
			int len_size = BN_num_bytes(decrypted_random);
			unsigned char *tmp_decrypt_text = (unsigned char *)malloc(len_size);
			BN_bn2bin(decrypted_random, (unsigned char *)tmp_decrypt_text);
			memcpy(decrypt_text + k*max_byte, tmp_decrypt_text, min(max_byte, str_len - k*max_byte));
			free(tmp_decrypt_text);
		}
		structBuffer.push_back(decrypt_text);
		structBuffer_length[i] = str_len;
	}

#define getfirst4bits(a) ((*(char *)(a)>>4)&0x0F)
#define getsecond4bits(a) (*(char *)(a)&0x0F)
#define getnext4bits(a, n) ((n)%2==0?getfirst4bits(a):getsecond4bits(a))
#define compareword(a, b) (a==b)
	std::vector<std::string> myVector;
	myVector.push_back("AA");
	myVector.push_back("AT");
	myVector.push_back("AG");
	myVector.push_back("AC");
	myVector.push_back("TT");
	myVector.push_back("GT");
	myVector.push_back("CT");
	myVector.push_back("GG");
	myVector.push_back("CG");
	myVector.push_back("CC");
	myVector.push_back(" ");
	myVector.push_back(";");
	myVector.push_back(".");

	std::vector<std::string> output;
	for (int i = 0; i < structBuffer.size(); i++)
	{
		unsigned char * tmp = structBuffer.at(i);
		std::string tmp_out = "";
		for (int j = 0; j < structBuffer_length[i]*2; j++)
		{		
			int k = 0;
			switch getnext4bits(tmp + (j / 2), j) {
				case	myHashMap_AA:  k = 1;  break;
				case	myHashMap_AT:  k = 2; break;
				case	myHashMap_AG:  k = 3;  break;
				case	myHashMap_AC:  k = 4;  break;
				case	myHashMap_TT:  k = 5;  break;
				case	myHashMap_GT:  k = 6;  break;
				case	myHashMap_CT:  k = 7;  break;
				case	myHashMap_GG:  k = 8;  break;
				case	myHashMap_CG:  k = 9;  break;
				case	myHashMap_CC:  k = 10;  break;
				case	myHashMap_sp:  k = 11;  break;
				case	myHashMap_sc:  k = 12;  break;
				case	myHashMap_pd:  k = 13;  break;
			default:
				assert(0);
				break;
			}			
			tmp_out += myVector[k-1];
			//if (k == 13) { break; }
		}
		output.push_back(tmp_out);
	}
	
	CreateTree(root, output);














	//char tempbuf[10000];
	//char* ptempbuf;
	//char finalBuf[10000];
	//int ifb = 0;
	//int index = 0;
	//int it = 0;

	/*while (buf[index] != NULL)
	{
		if (buf[index] == ';')
		{
			BN_dec2bn(&encrypted_random, tempbuf);
			emptyChar(tempbuf);
			decrypt(decrypted_random, encrypted_random, &keys.priv, ctx);
			ptempbuf = BN_bn2dec(decrypted_random);
			for (int i = 0; i < strlen(ptempbuf); i++)
			{
				finalBuf[ifb] = ptempbuf[i];
				ifb += 1;
			}
			it = 0;
			index += 1;
		}
		else
		{
			tempbuf[it] = buf[index];
			it += 1;
			index += 1;
		}
	}
	int i = 0;
	buf = finalBuf;
	decode(buf);// return decode buf
//	memcpy(buf, finalBuf, strlen(finalBuf) + 1);

	std::vector<std::string> DV;
	DV.push_back(" ");
	DataVector.push_back(DV);
	int bufIndex = 0;
	int bufPreIndex = 0;

	while (buf[bufIndex]<48 || buf[bufIndex]>57)
	{
		if (buf[bufIndex] == '.')
		{
			DV.clear();
			char temp[10000];
			for (int i = bufPreIndex; i < bufIndex; i++)
				temp[i-bufPreIndex] = buf[i];
			std::string tempS = temp;
			tempS=tempS.substr(0,bufIndex-bufPreIndex);
			int preIndex = 0;
			for (int i = 0; i < tempS.length(); i++)
			{
				if (tempS[i] == ';')
				{
					std::string ts = tempS;
					ts=ts.substr(preIndex, i-preIndex);
					DV.push_back(ts);
					preIndex = i + 1;
				}
			}
			DataVector.push_back(DV);
			bufPreIndex = bufIndex + 1;
		}
		bufIndex++;
	}*/
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//used for query------------------------------------------------------------------

void transferQuery(std::vector<std::string>& queryVector, char* query)
{
	int queryIndex = 0;
	int numFlag = 1;
	int lvlNum = 0;
	std::string temp="";
	char word[2];
	int wordIndex = 0;
	while (query[queryIndex] != NULL)
	{
		if (query[queryIndex] >= 48 && query[queryIndex] <= 57)
		{
			lvlNum = (query[queryIndex] - 48)+ lvlNum*numFlag;
			numFlag = 10;
			temp = std::to_string(lvlNum);
		}
		else if (query[queryIndex] == 32 || query[queryIndex] == ';')
		{
			numFlag = 1;
			lvlNum = 0;
			wordIndex = 0;
			queryVector.push_back(temp);
			temp = "";
		}
		else
		{
			word[wordIndex] = query[queryIndex];
			wordIndex += 1;
			if (wordIndex == 2)
			{
				temp = word;
				temp = temp.substr(0, 2);
			}
		}
		queryIndex++;
	}
}

void intTochar(char* temp,int num)
{
	std::vector<int> nt;
	if (num == 0)
		nt.push_back(0);
	while (num != 0)
	{
		nt.push_back(num%10);
		num = num / 10;
	}
	for (int i = 0; i < nt.size(); i++)
		temp[i] = nt[nt.size() - 1 - i] + 48;
}

void Query(char* query, size_t len)
{
	std::vector<std::string> queryVector;
	transferQuery(queryVector, query);
	std::vector<int> positionV;

	BFS(queryVector,positionV);

	// get position and make it return-------------------------
	char tposition[10000];
	int j = 0;
	for (int i = 0; i < positionV.size(); i++)
	{
		char temp[8]{ '!','!','!','!','!','!','!','!' };
		intTochar(temp, positionV[i]);
		int flag = 0;
		while (temp[flag] != '!')
		{
			tposition[j] = temp[flag];
			flag += 1;
			j += 1;
		}
		if (i == positionV.size() - 1)
		{
			tposition[j] = ';';
			break;
		}
		tposition[j] = ' ';
		j += 1;
	}

	memcpy(query, tposition, strlen(tposition) + 1);

//	std::vector<std::size_t> positionV;
//	std::size_t startPosition=0;
//	std::size_t endPosition = 1;
//	std::size_t wordsCount = 0;
//	std::size_t distance = 0;
//	std::size_t queryIndex = 2;
//
//// this part is used for initialize the fisrt query-------------
//	int Lvl = atoi(queryVector[0].c_str());
//	positionV.push_back(Lvl);
//	for (std::size_t i = 0; i < DataVector[Lvl].size(); i++)
//	{
//		std::size_t found = DataVector[Lvl][i].find(queryVector[1]);
//		if (found != std::string::npos)
//		{
//			wordsCount += found / 3;
//			startPosition = wordsCount;
//			positionV.push_back(wordsCount);
//			break;
//		}
//		wordsCount += (DataVector[Lvl][i].length() + 1) / 3;
//	}
//	Lvl += 1;
//	endPosition += 1;
//
//// this part is used to create the loop for query---------------
//	while(queryIndex< queryVector.size())
//	{
//		wordsCount = 0;
//		if (Lvl != atoi(queryVector[queryIndex].c_str()))
//		{
//			distance = 0;
//			for (int j = 0; j < startPosition; j++)
//				wordsCount += (DataVector[Lvl][j].length() + 1) / 3;
//			for (int j = startPosition; j < endPosition; j++)
//				distance += (DataVector[Lvl][j].length() + 1) / 3;
//			startPosition = wordsCount;
//			endPosition = startPosition + distance;
//			Lvl += 1;
//		}
//		else
//		{
//			positionV.push_back(Lvl);
//			for (int j = 0; j < startPosition; j++)
//				wordsCount += (DataVector[Lvl][j].length() + 1) / 3;
//			for (std::size_t i = startPosition; i < endPosition; i++)
//			{
//				std::size_t found = DataVector[Lvl][i].find(queryVector[queryIndex+1]);
//				if (found != std::string::npos)
//				{
//					wordsCount += found / 3;
//					startPosition = wordsCount;
//					positionV.push_back(startPosition);
//					break;
//				}
//				wordsCount += (DataVector[Lvl][i].length() + 1) / 3;
//			}
//			Lvl += 1;
//			endPosition = startPosition+1;
//			queryIndex += 2;
//		}
//	}


}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//generate the key-----------------------------------------
void generateKey(char* publicKey,size_t publicKeyLen)
{
	char pk[10000];
	int len = 1024;
	int index = 0;
	generateRandomKeys(&keys, &len, ctx);
	char *strn= BN_bn2dec(keys.pub.n);
	char *strn2= BN_bn2dec(keys.pub.n2);
	char *strg= BN_bn2dec(keys.pub.g);
	for (int i = 0; i < strlen(strn); i++)
	{
		pk[index] = strn[i];
		index += 1;
	}
	pk[index] = ';';
	index += 1;
	for (int i = 0; i < strlen(strn2); i++)
	{
		pk[index] = strn2[i];
		index += 1;
	}
	pk[index] = ';';
	index += 1;
	for (int i = 0; i < strlen(strg); i++)
	{
		pk[index] = strg[i];
		index += 1;
	}
	pk[index] = ';';
	index += 1;
	memcpy(publicKey, pk, strlen(pk) + 1);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void enclaveAddition(char* additionResult,size_t easlen)
{
	long long decrypted = 0;
	BIGNUM *encrypted_random = BN_CTX_get(ctx);
	BIGNUM *decrypted_random = BN_CTX_get(ctx);
	BN_dec2bn(&encrypted_random, additionResult);
	decrypt(decrypted_random, encrypted_random, &keys.priv, ctx);
	additionResult = BN_bn2dec(decrypted_random);
}