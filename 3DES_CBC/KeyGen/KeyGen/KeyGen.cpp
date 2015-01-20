// KeyGen.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <fstream> 

using namespace std;

#include "..\..\..\osrng.h"

using CryptoPP::AutoSeededRandomPool;

#include <iostream>

using std::cout;

using std::cerr;

using std::endl;

#include <conio.h>

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

#include "..\..\..\des.h"

using CryptoPP::DES_EDE3;

#include "..\..\..\modes.h"

using CryptoPP::CBC_Mode;

#include "..\..\..\secblock.h"

using CryptoPP::SecByteBlock;

#include "..\..\..\sha.h"

#include "..\..\..\md5.h"

int main(int argc, char* argv[])

{

	string cipher, encoded, recovered, decoded;

	AutoSeededRandomPool prng;

	SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);

	prng.GenerateBlock(key, key.size());

	//cout << “key generated using prng” << key << endl;

	encoded.clear();

	StringSource ss1(key, key.size(), true,

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