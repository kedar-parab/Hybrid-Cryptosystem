// Decrypt.cpp : Defines the entry point for the console application.
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
#include <time.h>
#include <iostream>
#include <string>
#include "..\..\..\modes.h"
#include "..\..\..\aes.h"
#include "..\..\..\filters.h"

int main(int argc, char* argv[])
{
	clock_t tStart = clock();
	string key, decodediv, cipher, recovered;

	std::ifstream ifs("..\\..\\key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.

	std::ifstream ifs1("..\\..\\ciphertext.txt");
	std::string cipher_content((std::istreambuf_iterator<char>(ifs1)),
		(std::istreambuf_iterator<char>()));
	//reading the file “encryptedplaintext.txt”

	std::string ivs = cipher_content.substr(0, 32);
	//pulling iv from encryptedplaintext.

	cipher_content.erase(0, 32);
	//erasing iv from encryptedplaintext.

	StringSource(content, true,
		new HexDecoder(
		new StringSink(key)
		) // HexEncoder
		); // StringSource
	//cout << “key converted from base16 to byte” << key << endl;

	StringSource(ivs, true,
		new HexDecoder(
		new StringSink(decodediv)
		) // HexEncoder
		); // StringSource
	//cout << “iv converted from base16 to byte” << decodediv << endl;

	string ciphertext;
	StringSource(cipher_content, true,
		new HexDecoder(
		new StringSink(cipher)
		) // HexEncoder
		); // StringSource
	//cout << “ciphertext converted from base16 to byte” << cipher << endl;

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
			new StringSink(recovered)
			) // StreamTransformationFilter
			); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)ciphertext.data(), ciphertext.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

		std::ofstream outfile("..\\..\\decryptedplaintext.txt");
		outfile << recovered << std::endl;
		outfile.close();
		//writing plaintext in the text file “decryptedplaintext.txt”.

	}
	catch (const CryptoPP::Exception& d)
	{
		cerr << d.what() << endl;
		exit(1);
	}

	cout << "AES_CBC Decryption Done!!" << endl;
	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC;
	_getch();
	return 0;
}