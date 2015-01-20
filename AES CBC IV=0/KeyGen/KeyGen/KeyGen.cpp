// KeyGen.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <cstdio>
#include <iostream>
#include <conio.h>
#include "..\..\..\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <fstream>  
using namespace std;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "..\..\..\cryptlib.h"
using CryptoPP::Exception;

#include "..\..\..\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "..\..\..\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "..\..\..\aes.h"
using CryptoPP::AES;

#include "..\..\..\modes.h"
using CryptoPP::CBC_Mode;

#include "..\..\..\secblock.h"
using CryptoPP::SecByteBlock;

#include <iostream>
#include <string>
#include "..\..\..\modes.h"
#include "..\..\..\aes.h"
#include "..\..\..\filters.h"


void F_CBC_MAC_KEYGEN()
{
	AutoSeededRandomPool prng;

	string cipher, encoded, recovered;

	byte key1[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key1, sizeof(key1));
	//cout << “key generated using prng” << key << endl;

	encoded.clear();
	StringSource(key1, sizeof(key1), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << “key encoded in base16 (hexadecimal) format” << encoded << endl;

	string k1 = encoded;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	//cout << “key generated using prng” << key << endl;

	byte key2[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key2, sizeof(key2));
	//cout << “key generated using prng” << key << endl;

	encoded.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << “key encoded in base16 (hexadecimal) format” << encoded << endl;

	string k2 = encoded;

	std::ofstream outfile("..\\..\\F_CBC_MAC_key.txt");
	outfile << k1 + k2;
	outfile.close();
	//writing readable hexadecimal key in the text file “key.txt”.

	cout << "F_CBC_MAC KEY GENERATED !!!!"<<endl<<endl;
}


void HMAC_SHA2_KEYGEN()
{
	AutoSeededRandomPool prng;

	string cipher, encoded, recovered;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	//cout << "key generated using prng" << key << endl;

	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << "key encoded in base16 (hexadecimal) format" << encoded << endl << endl;

	SecByteBlock hmackey(16);
	prng.GenerateBlock(hmackey, hmackey.size());
	//cout << "hmac key" << hmackey << endl;

	string newhmackey;
	StringSource(hmackey, sizeof(hmackey), true,
		new HexEncoder(
		new StringSink(newhmackey)
		) // HexEncoder
		); // StringSource
	//cout << "hmackey encoded in base16 (hexadecimal) format" << newhmackey << endl << endl;

	string key_hmackey = encoded + newhmackey;
	//cout << "key_hmackey" << key_hmackey << endl << endl;

	std::ofstream outfile("..\\..\\HMAC_SHA2_key.txt");
	outfile << key_hmackey << std::endl;
	outfile.close();
	//writing readable hexadecimal key in the text file “key.txt”.

	cout << "HMAC SHA2 KEY GENERATED !!!!"<<endl<<endl;
}


void PRF_MAC_KEYGEN()
{
	AutoSeededRandomPool prng;

	string cipher, encoded, recovered;

	byte key1[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key1, sizeof(key1));
	//cout << “key generated using prng” << key << endl;

	encoded.clear();
	StringSource(key1, sizeof(key1), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << “key encoded in base16 (hexadecimal) format” << encoded << endl;

	string k1 = encoded;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	//cout << “key generated using prng” << key << endl;

	byte key2[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key2, sizeof(key2));
	//cout << “key generated using prng” << key << endl;

	encoded.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << “key encoded in base16 (hexadecimal) format” << encoded << endl;

	string k2 = encoded;

	std::ofstream outfile("..\\..\\PRF_MAC_key.txt");
	outfile << k1 + k2;
	outfile.close();
	//writing readable hexadecimal key in the text file “key.txt”.

	cout << "PRF_MAC KEY GENERATED !!!!"<<endl<<endl;

}
int main(int argc, char* argv[])
{
	F_CBC_MAC_KEYGEN();
	HMAC_SHA2_KEYGEN();
	PRF_MAC_KEYGEN();

	_getch();
	return 0;
}