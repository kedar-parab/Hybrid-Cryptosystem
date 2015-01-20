// Encrypt.cpp : Defines the entry point for the console application.
//

// Encrypt.cpp : Defines the entry point for the console application.
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

#include <time.h>

int main(int argc, char* argv[])

{
	clock_t tStart = clock();

	string cipher, ciphertext, ciphertextnew, ivnew, recovered,

		decoded, ivdecoded;

	AutoSeededRandomPool prng;

	byte iv[DES_EDE3::BLOCKSIZE];

	prng.GenerateBlock(iv, sizeof(iv));

	//cout << “iv generated using prng” << iv << endl;

	StringSource(iv, sizeof(iv), true,

		new HexEncoder(

		new StringSink(ivnew)

		) // HexEncoder

		); // StringSource

	//cout << “iv encoded in base16 (hexadecimal) format” << ivnew << endl;

	std::ifstream ifs("..\\..\\key.txt");

	std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

	//reading the file “key.txt”.

	try

	{
		std::ifstream ifs("..\\..\\plaintext.txt");
		std::string plain((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
		StringSource ss(content, true,

			new HexDecoder(

			new StringSink(decoded)

			) // HexDecoder

			); // StringSource

		//cout << “key converted from base16 to byte” << decoded << endl;

		CBC_Mode< DES_EDE3 >::Encryption e;

		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), iv);

		//The StreamTransformationFilter adds padding as required. 

		//ECB and CBC Mode must be padded to the block size of the cipher.

		StringSource(plain, true,

			new StreamTransformationFilter(e,

			new StringSink(cipher)

			) // StreamTransformationFilter 

			); // StringSource

		StringSource(cipher, true,

			new HexEncoder(

			new StringSink(ciphertext)

			) // HexEncoder

			); // StringSource

		//cout << “ciphertext encoded in base16 (hexadecimal) format” << ciphertext << endl;

		ciphertextnew = ivnew + ciphertext;

		//cout << “pre-appending iv to the ciphertext” << ciphertextnew << endl;

		std::ofstream outfile("..\\..\\ciphertext.txt");

		outfile << ciphertextnew << std::endl;

		outfile.close();

		//writing readable hexadecimal ciphertext in the text file “encryptedplaintext.txt”.

	}

	catch (const CryptoPP::Exception& e)

	{

		cerr << e.what() << endl;

		exit(1);

	}

	cout << "3DES Ciphertext Generated!!" << endl;

	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC;

	_getch();

	return 0;

}