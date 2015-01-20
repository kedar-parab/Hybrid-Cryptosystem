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

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	string cipher, encoded, recovered;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	//cout << “key generated using prng” << key << endl;

	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << “key encoded in base16 (hexadecimal) format” << encoded << endl;

	std::ofstream outfile("..\\..\\key.txt");
	outfile << encoded << std::endl;
	outfile.close();
	//writing readable hexadecimal key in the text file “key.txt”.

	cout << "KEY GENERATED !!!!";
	_getch();
	return 0;
}