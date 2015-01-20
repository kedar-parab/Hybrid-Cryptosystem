// Encrypt.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <cstdio>
#include <iostream>
#include <conio.h>
#include <sstream>
#include <iomanip>
#include <time.h>
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

#include "..\..\..\hmac.h"
using CryptoPP::HMAC;

#include "..\..\..\sha.h"
using CryptoPP::SHA256;

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
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;
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
void F_CBC_MAC(string decodediv)
{
	clock_t tStart = clock();
	string cipher, ciphertext, decoded, ivdecoded, cipher_timestamp, ciphertext_timestamp;
	std::ifstream ifs("..\\..\\F_CBC_MAC_key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.
	//cout << "k1 + k2  " << content << endl;
	string k2 = content.substr(32, 64);
	//cout << "k2 " << k2 << endl;
	content.erase(32, 64);
	//cout << "k1  " << content << endl;
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
		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), (byte*)decodediv.c_str());

		//cout << "decoded "<<decoded <<endl;
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
	//cout << "ciphertext encoded in base16 (hexadecimal) format" << ciphertext << endl;
	string k2decoded;
	string last_block = ciphertext.substr(ciphertext.length() - 30, ciphertext.length());
	//cout << "last_block" << last_block << endl;

	int len = last_block.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = last_block.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), 0, 16);
		newString.push_back(chr);
	}
	//cout << "hex to ascii output" << newString << endl;

	//cout << "last block " << last_block << endl;
	StringSource(k2, true,
		new HexDecoder(
		new StringSink(k2decoded)
		) // HexEncoder
		); // StringSource
	//cout << "key converted from base16 to byte" << k2decoded << endl;
	CBC_Mode< AES> ::Encryption e1;
	e1.SetKeyWithIV((byte*)k2decoded.c_str(), k2decoded.size(), (byte*)decodediv.c_str());
	string tag;
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s1(newString, true,
		new StreamTransformationFilter(e1,
		new StringSink(tag)
		) // StreamTransformationFilter
		); // StringSource

#if 0
	StreamTransformationFilter filter(e1);
	filter.Put((const byte*)newString.data(), newString.size());
	filter.MessageEnd();

	const size_t ret = filter.MaxRetrievable();
	cipher.resize(ret);
	filter.Get((byte*)tag.data(), tag.size());
#endif

	//cout << "tag " << tag << endl;

	string hextag;
	StringSource(tag, true,
		new HexEncoder(
		new StringSink(hextag)
		) // HexEncoder
		); // StringSource

	//cout << "tag hex format " << hextag << endl;

	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	//cout << "Current local time and date: " << asctime(timeinfo) << endl;

	try
	{
		CBC_Mode< AES> ::Encryption e;
		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), (byte*)decodediv.c_str());

		//cout << "decoded "<<decoded <<endl;
		// The StreamTransformationFilter removes
		//  padding as required.

		StringSource(asctime(timeinfo), true,
			new StreamTransformationFilter(e,
			new StringSink(cipher_timestamp)
			) // StreamTransformationFilter
			); // StringSource
		//cout << "timestamp in byte format : " << cipher_timestamp << endl << endl;

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)asctime(timeinfo).data(), asctime(timeinfo).size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher_timestamp.data(), cipher_timestamp.size());
#endif
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	StringSource(cipher_timestamp, true,
		new HexEncoder(
		new StringSink(ciphertext_timestamp)
		) // HexEncoder
		); // StringSource
	//cout << "timestamp in hex format : " << ciphertext_timestamp << endl << endl;
	/*
	string timestamphex;
	StringSource(asctime(timeinfo), true,
	new HexEncoder(
	new StringSink(timestamphex)
	) // HexEncoder
	);
	//cout << "timestamphex" << timestamphex << endl;
	*/
	string data = ciphertext_timestamp + ciphertext + hextag;
	//cout << "final data" << data << endl;

	std::ofstream outfile1("..\\..\\F_CBC_MAC_ciphertext.txt");
	outfile1 << data <<std::endl;
	outfile1.close();
	//writing readable hexadecimal ciphertext in the text file “encryptedplaintext.txt”.

	cout << "Ciphertext Generated using AES_CBC with IV=0 and HMAC_SHA2 scheme " << endl << endl;

	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC<<endl;
}
void HMAC_SHA2(string decodediv)
{
	clock_t tStart = clock();
	string cipher, ciphertext, decoded, ivdecoded;
	string timestamphex;
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	//cout << "Current local time and date: " << asctime(timeinfo) << endl;

	StringSource(asctime(timeinfo), true,
		new HexEncoder(
		new StringSink(timestamphex)
		) // HexEncoder
		);
	//cout << "HEX Timestamp: " << timestamphex << endl;

	std::ifstream ifs("..\\..\\HMAC_SHA2_key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.
	//cout << "encryption key" << content<<endl;
	string hmackey = content.substr(32, 64);
	//cout << "hmackey " << hmackey << endl;
	content.erase(32, 64);
	//cout << "key  " << content << endl;

	int len = hmackey.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = hmackey.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), 0, 16);
		newString.push_back(chr);
	}
	//cout << "hex to ascii output" << newString << endl;

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
		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), (byte*)decodediv.c_str());

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

	cout << "Ciphertext Generated using AES_CBC with IV=0 and HMAC_SHA2 scheme " << endl;

	string mac, encoded;
	//cout << "ciphertext" << ciphertext <<endl;

	std::string ct_ts = ciphertext + timestamphex;
	/*********************************\
	\*********************************/

	//cout << "concat string of cipher and time" << ct_ts << endl;

	byte* b = (byte*)newString.c_str();

	// Pretty print key
	encoded.clear();
	StringSource(b, sizeof(b), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << "key: " << encoded << endl<<endl;

	//cout << "plain text: " << plain << endl;

	/*********************************\
	\*********************************/
	//cout << "hmackey " << hmackey << endl << endl;
	try
	{
		HMAC< SHA256 > hmac(b, sizeof(b));
		//cout << "Sizes  " << newString.size() << endl << endl;
		//cout << "HMACKEY " << newString << endl << endl;
		StringSource(ct_ts, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
		//cout << "hmac " << mac << endl << endl;

	}
	catch (const CryptoPP::Exception& ex)
	{
		cerr << ex.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print MAC
	encoded.clear();
	StringSource(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << "mac in hex: " << encoded << endl << endl;
	//cout << "size of mac" << encoded.size() << endl;
	string tag = encoded;

	string data = timestamphex + ciphertext + tag;

	//cout << "Data " << data << endl;

	/*********************************\
	\*********************************/



	std::ofstream outfile("..\\..\\HMAC_SHA2_ciphertext.txt");
	outfile << data;
	outfile.close();
	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC<<endl<<endl;
}
void PRF_MAC(string decodediv)
{
	clock_t tStart = clock();
	string cipher, ciphertext, decoded, ivdecoded, cipher_timestamp, ciphertext_timestamp;

	std::ifstream ifs("..\\..\\PRF_MAC_key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.
	//cout << "k1 + k2  " << content << endl;
	string k2 = content.substr(32, 64);
	//cout << "k2 " << k2 << endl;
	content.erase(32, 64);
	//cout << "k1  " << content << endl;
	try
	{
		std::ifstream ifsp("..\\..\\plaintext.txt");
		std::string contentp((std::istreambuf_iterator<char>(ifsp)),
			(std::istreambuf_iterator<char>()));
		string plain = contentp;
		//cout << "plain length " << plain.length() << endl << endl;
		StringSource(content, true,
			new HexDecoder(
			new StringSink(decoded)
			) // HexEncoder
			); // StringSource
		//cout << “key converted from base16 to byte” << decoded << endl;
		//cout << "decoded length" << decoded.length() << endl << endl;
		CBC_Mode< AES> ::Encryption e;
		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
			new StringSink(cipher)
			) // StreamTransformationFilter
			); // StringSource
		//cout << "cipher " << cipher << endl;
		//cout << "cipher length " << cipher.length() << endl << endl;

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
	//cout << "ciphertext encoded in base16 (hexadecimal) format" << ciphertext << endl;

	string timestamphex;
	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	//cout << "Current local time and date: " << asctime(timeinfo);

	try
	{
		CBC_Mode< AES> ::Encryption e;
		e.SetKeyWithIV((byte*)decoded.c_str(), decoded.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.

		StringSource(asctime(timeinfo), true,
			new StreamTransformationFilter(e,
			new StringSink(cipher_timestamp)
			) // StreamTransformationFilter
			); // StringSource
		//cout << "timestamp in byte format : " << cipher_timestamp << endl << endl;

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)asctime(timeinfo).data(), asctime(timeinfo).size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher_timestamp.data(), cipher_timestamp.size());
#endif
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	StringSource(cipher_timestamp, true,
		new HexEncoder(
		new StringSink(ciphertext_timestamp)
		) // HexEncoder
		); // StringSource
	//cout << "timestamp in hex format : " << ciphertext_timestamp << endl << endl;
	/*
	StringSource(asctime(timeinfo), true,
	new HexEncoder(
	new StringSink(timestamphex)
	) // HexEncoder
	);
	cout << "hex timestamp" << timestamphex << endl;
	*/


	int len = ciphertext.length();
	//cout << "ciphertext length" << len << endl;
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = ciphertext.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), 0, 16);
		newString.push_back(chr);
	}
	//cout << "hex to ascii output" << newString << endl;
	//cout << "Ascii length " << newString.length() << endl;


	string k2decoded;
	//cout << "K2 size: " << k2.length() << endl;
	StringSource(k2, true,
		new HexDecoder(
		new StringSink(k2decoded)
		) // HexEncoder
		); // StringSource
	//cout << "IV length " << decodediv.length() << endl << endl;
	//cout << "k2 decoded " << k2decoded.length() << endl << endl;
	//cout << “key converted from base16 to byte” << decoded << endl;
	CBC_Mode< AES> ::Encryption e1;
	e1.SetKeyWithIV((byte*)k2decoded.c_str(), k2decoded.size(), (byte*)decodediv.c_str());
	string tag;
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s1(newString, true,
		new StreamTransformationFilter(e1,
		new StringSink(tag)
		) // StreamTransformationFilter
		); // StringSource
	//cout << "first tag " << tag << endl;
	//cout << "size of first tag " << tag.length() << endl;


#if 0
	StreamTransformationFilter filter(e1);
	filter.Put((const byte*)newString.data(), newString.size());
	filter.MessageEnd();

	const size_t ret = filter.MaxRetrievable();
	cipher.resize(ret);
	filter.Get((byte*)tag.data(), tag.size());
#endif


	string hextag;
	StringSource(tag, true,
		new HexEncoder(
		new StringSink(hextag)
		) // HexEncoder
		); // StringSource

	//cout << "tag hex format " << hextag << endl;
	//cout << "Size of hextag : " << hextag.length() << endl;

	string data = ciphertext_timestamp + ciphertext + hextag;
	//cout << "data is: " << data << endl << endl;


	std::ofstream outfile1("..\\..\\PRF_MAC_ciphertext.txt");
	outfile1 << data;
	outfile1.close();
	//writing readable hexadecimal ciphertext in the text file “encryptedplaintext.txt”.

	cout << "Ciphertext Generated using AES_CBC with IV=0 and PRF_MAC scheme" <<endl;

	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC <<endl;
}
int main(int argc, char* argv[])
{
	string decodediv;
	string iv = "00000000000000000000000000000000";

	StringSource(iv, true,
		new HexDecoder(
		new StringSink(decodediv)
		) // HexEncoder
		); // StringSource
	//cout << “iv converted from base16 to byte” << decodediv << endl;
	int n;
	cout << "Choose the scheme you want to employ" << endl;
	cout << "1. F_CBC_MAC" << endl;
	cout << "2. HMAC_SHA2" << endl;
	cout << "3. PRF_MAC" << endl;
	cout << "4. EXIT" << endl;
	
	do {
	cin >> n;
	switch (n){
	case 1:
		F_CBC_MAC(decodediv);
		break;
	case 2:		
		HMAC_SHA2(decodediv);
		break;
	case 3:		
		PRF_MAC(decodediv);
		break;
	case 4:
		break;
	}

	} while (n != 4);
	_getch();

	return 0;
}