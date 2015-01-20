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
	string cipher, ciphertext, ivnew, decoded, ivdecoded;
	AutoSeededRandomPool prng;

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	//cout << “iv generated using prng” << iv << endl;	

	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
		new StringSink(ivnew)
		) // HexEncoder
		); // StringSource
	//cout << “iv encoded in base16 (hexadecimal) format” << ivnew << endl;

	std::ifstream ifs("..\\..\\key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.

	try
	{
		std::ifstream ifsp("..\\..\\plaintext.txt");
		std::string contentp((std::istreambuf_iterator<char>(ifsp)),
			(std::istreambuf_iterator<char>()));
		
		string plain = contentp;

		StringSource(content, true,
			new HexDecoder(
			new StringSink(decoded)
			) // HexEncoder
			); // StringSource
		//cout << “key converted from base16 to byte” << decoded << endl;

		CBC_Mode< AES> ::Encryption e;
		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
			new StringSink(cipher)
			) // StreamTransformationFilter
			); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	StringSource(cipher, true,
		new HexEncoder(
		new StringSink(ciphertext)
		) // HexEncoder
		); // StringSource
	//cout << “ciphertext encoded in base16 (hexadecimal) format” << ciphertext << endl;

	std::ofstream outfile1("..\\..\\ciphertext.txt");
	outfile1 << ivnew + ciphertext << std::endl;
	outfile1.close();
	//pre-appending iv to the ciphertext and writing readable hexadecimal ciphertext in the text file “encryptedplaintext.txt”.

	cout << "AES_CBC Ciphertext Generated!!" << endl;
	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC;

	_getch();

	return 0;
}