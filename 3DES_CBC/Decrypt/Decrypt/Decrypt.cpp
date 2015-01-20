// Decrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

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

#include <fstream> 

using namespace std;

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

int _tmain(int argc, _TCHAR* argv[])

{
	clock_t tStart = clock();

	string key, decodediv, cipher, recovered;

	std::ifstream ifs("..\\..\\key.txt");

	std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

	//reading the file “key.txt”.

	std::ifstream ifss("..\\..\\ciphertext.txt");

	std::string ciphertext((std::istreambuf_iterator<char>(ifss)), std::istreambuf_iterator<char>());

	//reading the file “encryptedplaintext.txt”

	std::string ivs = ciphertext.substr(0, 16);

	//pulling iv from ciphertext.

	ciphertext.erase(0, 16);

	//erasing iv from ciphertext.

	StringSource ss2(content, true,

		new HexDecoder(

		new StringSink(key)

		) // HexEncoder

		); // StringSource

	//cout << “key converted from base16 to byte” << key << endl;

	StringSource ss3(ivs, true,

		new HexDecoder(

		new StringSink(decodediv)

		) // HexEncoder

		); // StringSource

	//cout << “iv converted from base16 to byte” << decodediv << endl;

	StringSource ss4(ciphertext, true,

		new HexDecoder(

		new StringSink(cipher)

		) // HexEncoder

		); // StringSource

	//cout << “ciphertext converted from base16 to byte” << cipher << endl;

	try

	{

		CBC_Mode< DES_EDE3 >::Decryption d;

		d.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes padding as required.

		StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered))); // StreamTransformationFilter); // StringSource

		std::ofstream outfile("..\\..\\decryptedplaintext.txt");

		outfile << recovered << std::endl;

		outfile.close();

		//writing plaintext in the text file “decryptedplaintext.txt”.

	}

	catch (const CryptoPP::Exception& e)

	{

		cerr << e.what() << endl;

		exit(1);

	}

	cout << "3DES Decryption Done!!" << endl;

	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC;

	_getch();

	return 0;

}