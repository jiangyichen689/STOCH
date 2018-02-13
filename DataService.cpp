#include <windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<vector>
#include<queue>
#include<fstream>
#include<iostream>
#include<ostream>
#include<string>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "HME.h"

// for OPENSSL---------------------------------------
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
		fprintf(stderr, "Error calculating lcm: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "Error calculating L: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "Key lenght too short. Minimum lenght 32 bits");
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
		//		srandom((int)buffer);

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
		fprintf(stderr, "Error generating keys: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "Can't encrypt %lld: %s", plain, ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "Message not in Zn");
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
		fprintf(stderr, "Error ecnrypting: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "Message provided not in Zn2");
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
		fprintf(stderr, "Can't decrypt: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "Can't decrypt: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "sub: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "subEncPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "subEncPlain: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "subllPlainEnc: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "subPlainEnc: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "add: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "addEncPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "addEncPlain: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "mulPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
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
		fprintf(stderr, "mulPlain: %s", ERR_error_string(ERR_get_error(), NULL));
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
////////////////////////////////////////////////////////////////////////////////////////////////////////////



// for tree-------------------------------------------------------------

struct TreeNode
{
	std::string val;
	int count=1;
	TreeNode* child;
	std::vector<TreeNode*> sibling;
	TreeNode(std::string x) : val(x), child(NULL) {}
};

void Insert(TreeNode* root, std::string value)
{
	TreeNode * temproot = new TreeNode(value);
	if (root->child == NULL)
		root->child = temproot;
	else
	{
		root->count += 1;
		root->sibling.push_back(temproot);
	}

}

void CreateTree(TreeNode* root, std::vector<std::vector<std::string>> test)
{
	for (size_t i = 0; i < test.size(); i++)
	{
		TreeNode* cur = root;
		for (size_t j = 0; j < test[0].size(); j++)
		{
			if (cur->child != nullptr&&cur->child->val == test[i][j])
			{
				cur->count += 1;
				cur = cur->child;
				continue;
			}
			else if (cur->sibling.size() > 0)
			{
				int k = 0;
				int size = cur->sibling.size();
				while (k < size)
				{
					if (cur->sibling[k]->val == test[i][j])
					{
						cur->count += 1;
						cur = cur->sibling[k];
						break;
					}
					k++;
				}
				if (k < size)
					continue;
			}
			Insert(cur, test[i][j]);
			if (cur->sibling.size() == 0)
				cur = cur->child;
			else
				cur = cur->sibling.back();
		}
	}
}

std::string encryptedInt(int num, paillierKeys keys)
{
	BN_CTX *ctx2 = BN_CTX_new();
	BIGNUM *random = BN_CTX_get(ctx2);
	BIGNUM *encrypted_random = BN_CTX_get(ctx2);
	std::string strnum = std::to_string(num);

	const char* tempS = strnum.c_str();
	BN_dec2bn(&random, tempS);
	encrypt(encrypted_random, random, &keys.pub, ctx2);
	tempS = BN_bn2dec(encrypted_random);
	return tempS;
}

void makeString(TreeNode* root,std::vector<std::string>& structString, std::vector<std::string>& countString, paillierKeys keys)
{
	std::queue<TreeNode*> treeQ;
	TreeNode* tempRoot;

	treeQ.push(root);
	while (!treeQ.empty())
	{
		std::string tempStructString = "";
		std::string tempCountString = "";
		int size = treeQ.size();
		for (int i = 0; i < size; i++)
		{
			tempRoot = treeQ.front();
			treeQ.pop();
			if (tempRoot->child != nullptr)
			{
				treeQ.push(tempRoot->child);
				if (tempRoot->sibling.size() == 0)
				{
					tempStructString += tempRoot->child->val + ";";
					// this tempRoot->child->count need encrypted--------------------------
					tempCountString += encryptedInt(tempRoot->child->count,keys) + ";";
				}
				else
				{
					tempStructString += tempRoot->child->val + " ";
					// this tempRoot->child->count need encrypted--------------------------
					tempCountString += encryptedInt(tempRoot->child->count,keys) + " ";
					for (size_t j = 0; j < tempRoot->sibling.size(); j++)
					{
						treeQ.push(tempRoot->sibling[j]);
						if (j == tempRoot->sibling.size() - 1)
						{
							tempStructString += tempRoot->sibling[j]->val + ";";
							// this tempRoot->sibling[j]->count need encrypted--------------------------
							tempCountString += encryptedInt(tempRoot->sibling[j]->count,keys) + ";";
						}
						else
						{
							tempStructString += tempRoot->sibling[j]->val + " ";
							// this tempRoot->sibling[j]->count need encrypted--------------------------
							tempCountString += encryptedInt(tempRoot->sibling[j]->count,keys) + " ";
						}
					}
				}
			}
		}
		if (tempStructString != "")
		{
			structString.push_back(tempStructString+".");
			countString.push_back(tempCountString+".");
		}
	}
}

std::string toBinary(std::string tmp)
{
	if (tmp == "AA"){
		return "0001";
	}
	else if (tmp == "AT"){
		return "0010";
	}
	else if (tmp == "AG"){
		return "0011";
	}
	else if (tmp == "AC"){
		return "0100";
	}
	else if (tmp == "TT"){
		return "0101";
	}
	else if (tmp == "GT"){
		return "0110";
	}
	else if (tmp == "CT"){
		return "0111";
	}
	else if (tmp == "GG"){
		return "1000";
	}
	else if (tmp == "CG"){
		return "1001";
	}
	else if (tmp == "CC"){
		return "1010";
	}
	else if (tmp == " "){
		return "1011";
	}
	else if (tmp == ";") {
		return "1100";
	}
	else if (tmp == "."){
		return "1101";
	}
}
unordered_map <string, string> myHashMap;

void buildHashMap()
{
    myHashMap["A"] = "00';
    myHashMap["T"] = "01';
    myHashMap["G"] = "10';
    myHashMap["C"] = "11';
    myHashMap[" "] = "0110"; //'TG'
    myHashMap[";"] = "0111"; //'TC'
    myHashMap["."] = "0100"; //'TA'
    
}

void encode(std::vector<std::string>& origin)
{
    int size = origin.size();
    for (int i = 0; i < size; i++)
    {
        std::string encodeString = "";
        int index = 0;
        while (index < origin[i].length())
        {
            encodeString +=myHashMap[origin[i][index]];
        }
        origin[i] = encodeString;
    }
}

void encode(std::vector<std::str
            
            ing>& origin)
{
	int size = origin.size();
	for (int i = 0; i < size; i++)
	{
		std::string encodeString = "";
		int index = 0;
		while (index < origin[i].length())
		{
			if (origin[i][index] == 'A' || origin[i][index] == 'T' || origin[i][index] == 'G' || origin[i][index] == 'C')
			{
				std::string tmp = origin[i].substr(index, 2);
				encodeString += toBinary(tmp);
				index += 2;
			}
			else if (origin[i][index] == ' ')
			{
				std::string tmp = origin[i].substr(index, 1);
				encodeString += toBinary(tmp);
				index += 1;
			}
			else if (origin[i][index] == ';')
			{
				std::string tmp = origin[i].substr(index, 1);
				encodeString += toBinary(tmp);
				index += 1;
			}
			else if (origin[i][index] == '.')
			{
				std::string tmp = origin[i].substr(index, 1);
				encodeString += toBinary(tmp);
				index += 1;
			}
		}
		origin[i] = encodeString;
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////

size_t key_size = BN_num_bytes(keyinBN);
fprintf()


void readKey(char* strn, char* strn2, char* strg, std::string path)
{
	char buffer[5000];
	std::fstream getFile;
	getFile.open(path, std::ios::in);

	getFile.getline(buffer, 5000, '\n');

	int separate = 0;
	int index = 0;

	if (separate == 0)
	{
		int i = 0;
		while (buffer[index] != ';')
		{
			strn[i] = buffer[index];
			i += 1;
			index += 1;
		}
	}
	index += 1;
	separate += 1;
	if (separate == 1)
	{
		int i = 0;
		while (buffer[index] != ';')
		{
			strn2[i] = buffer[index];
			i += 1;
			index += 1;
		}
	}
	index += 1;
	separate += 1;
	if (separate == 2)
	{
		int i = 0;
		while (buffer[index] != ';')
		{
			strg[i] = buffer[index];
			i += 1;
			index += 1;
		}
	}
}


void getBuffer(std::vector<std::vector<std::string>>&  structBuffer, std::string path)
{
	std::vector<std::string> sb;
	char buffer[100000];
	std::fstream getFile;
	getFile.open(path, std::ios::in);
	int index = 0;
	while (!getFile.eof())
	{
		getFile.getline(buffer, 100000, '\n');
		int i = 0;
		sb.clear();
		while (buffer[i] >=65 && buffer[i]<=90)
		{
			char temp[2];
			for (int j = 0; j < 2; j++)
			{
				temp[j] = buffer[i];
				i += 1;
			}
			std::string tmps = temp;
			sb.push_back(tmps.substr(0, 2));
			i += 1;
		}
		structBuffer.push_back(sb);
	}
}


// for main function----------------------------------------------------------------------
#define KEY_LEN 64
#define MAX_M_BITS 22

#define MAX_SUB_LEN MAX_M_BITS
#define SUB_CORRECTION_FACTOR MAX_M_BITS+1

#define MAX_MULT_FACTOR_LEN KEY_LEN - MAX_M_BITS -1


int main()
{
// initailizing the timer-------------------------
	LARGE_INTEGER f;
	QueryPerformanceFrequency(&f);

	double dFreq, duration;
	dFreq = (double)f.QuadPart; 

	LARGE_INTEGER start, end;
/////////////////////////////////////////////////////////////////////

// get test file------------------------------------------------
	std::vector<std::vector<std::string>> testCase;
	std::string path1="C:\\Users\\user\\Desktop\\testcase\\testcase.txt";
	getBuffer(testCase,path1);
////////////////////////////////////////////////////////////////////

//get key-------------------------------------------------------
	int len = 0;

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *random = BN_CTX_get(ctx);
	BIGNUM *encrypted_random = BN_CTX_get(ctx);

	paillierKeys keys;
	len = 1024;
	generateRandomKeys(&keys, &len, ctx);

	BIGNUM *n = BN_CTX_get(ctx);
	BIGNUM *n2 = BN_CTX_get(ctx);
	BIGNUM *g = BN_CTX_get(ctx);

	char strn[1000];
	char strn2[1000];
	char strg[1000];
	std::string path = "C:\\Users\\user\\Desktop\\GenerateFile\\publicKey.txt";
	std::fstream getFile;
	getFile.open(path, std::ios::in);
	while (!getFile)
	{
		getFile.close();
		Sleep(2000);
		getFile.open(path, std::ios::in);
	}
	getFile.close();
	readKey(strn,strn2,strg,path);
	BN_dec2bn(&keys.pub.n, strn);
	BN_dec2bn(&keys.pub.n2, strn2);
	BN_dec2bn(&keys.pub.g, strg);
//////////////////////////////////////////////////////////////////////////

	QueryPerformanceCounter(&start);
//create tree--------------------------------------------------
	TreeNode* root = new TreeNode(" ");
	CreateTree(root, testCase);
//////////////////////////////////////////////////////////////////
	QueryPerformanceCounter(&end);
	duration = (double)(end.QuadPart - start.QuadPart) / dFreq;
	printf(" Time of building the tree: %f\n", duration);

	QueryPerformanceCounter(&start);
// encrypted the data----------------------------------------
	std::ofstream write1;
	std::ofstream write2;
	write1.open("C:\\Users\\user\\Desktop\\GenerateFile\\struct.txt", std::ios::trunc);
	write2.open("C:\\Users\\user\\Desktop\\GenerateFile\\count.txt", std::ios::trunc);

	std::vector<std::string> structString;
	std::vector<std::string> countString;
	makeString(root, structString, countString,keys);
	std::cout << "struct string is done" << std::endl;
	encode(structString);
	std::cout << "encoding is done" << std::endl;

	QueryPerformanceCounter(&start);
	for (int i = 0; i < structString.size(); i++)
	{
		std::string seps = structString[i]; // binary 4 bits per word.
        int max_bits = 1000;  // 125 byte;
		while (seps.size() > max_bits)
		{
			const char* tempS = seps.substr(0,max_bits).c_str();
            char tempS[1024];  // here you need 1024/8
            
            String s = '00000001';
            BN_bin2bn(s.c_str(), 8, &random);
            BN_bn2bin(&random, ss);
            
			seps.erase(0, max_bits);
			BN_bin2bn(tempS, max_bits, &random); // https://linux.die.net/man/3/bn_bin2bn
            BN_bn2bin(&random, &tempSS); // BN_bn2bin() converts the absolute value of a into big-endian form and stores it at to. to must point to BN_num_bytes(a) bytes of memory.
			encrypt(encrypted_random, random, &keys.pub, ctx);
			BN_bn2bin(encrypted_random, outBuffer);
            
			write1.write(tempS, strlen(tempS));
			write1 << " ";
		}
		const char* tempS = seps.c_str();
		BN_dec2bn(&random, tempS);
		encrypt(encrypted_random, random, &keys.pub, ctx);
		tempS = BN_bn2dec(encrypted_random);
		write1.write(tempS, strlen(tempS));
		write1 << "\n";

		const char* tempC = countString[i].c_str();
		write2.write(tempC, strlen(tempC));
		write2 << "\n";
	}
///////////////////////////////////////////////////////////////////////
	QueryPerformanceCounter(&end);
	duration = (double)(end.QuadPart - start.QuadPart) / dFreq;
	printf(" Total encrypted time: %f\n", duration);

	write1.close();
	write2.close();

	system("pause");
}
