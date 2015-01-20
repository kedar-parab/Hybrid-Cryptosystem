// KeyGen.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <cstdio>
#include <iostream>
#include <conio.h>
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

#include <cstdlib>
using std::exit;

#include "..\..\..\hmac.h"
using CryptoPP::HMAC;

#include "..\..\..\sha.h"
using CryptoPP::SHA256;

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

#include "..\..\..\files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "..\..\..\dsa.h"
using CryptoPP::DSA;


#include "..\..\..\base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "..\..\..\cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "..\..\..\SecBlock.h"
using CryptoPP::SecByteBlock;


#include "..\..\..\sha.h"
using CryptoPP::SHA1;

#include "..\..\..\dsa.h"
using CryptoPP::DSA;

#include "..\..\..\queue.h"
using CryptoPP::ByteQueue;

#include <iostream>
#include <string>
#include "..\..\..\modes.h"
#include "..\..\..\aes.h"
#include "..\..\..\filters.h"
#include "..\..\..\rsa.h"
using CryptoPP::RSA;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::InvertibleRSAFunction;

#include "..\..\..\oaep.h"
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
#include "..\..\..\sha.h"
using CryptoPP::SHA1;

#include <string>
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void Save(const string& filename, const BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

int main(int argc, char* argv[])
{
	/////////////////////////////////////////////////
	clock_t tStart = clock();
	string decodediv;
	string iv = "00000000000000000000000000000000";

	StringSource(iv, true,
		new HexDecoder(
		new StringSink(decodediv)
		) // HexEncoder
		); // StringSource
	//cout << "iv converted into base 16 format " << decodediv << endl;

	string ciphertext, decoded, ivdecoded;
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

	//////////////////////////////////////////////////////////////////////
	AutoSeededRandomPool prng;

	string cipher, encoded, recovered;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	//cout << "key generated using prng " << key << endl;

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

	string symmetric_key = encoded + newhmackey;
	//cout << "symmetric key :" << symmetric_key << endl;

	//cout << "key_hmackey" << symmetric_key << endl << endl;

	int len = newhmackey.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = newhmackey.substr(i, 2);
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
		//cout << "\nplain text :" << plain << endl;

		StringSource(encoded, true,
			new HexDecoder(
			new StringSink(decoded)
			) // HexEncoder
			); // StringSource
		//cout << "key converted from base16 to byte " << decoded << endl;

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
	//cout << "ciphertext encoded in base16 (hexadecimal) format " << ciphertext << endl;


	string mac;
	//cout << "ciphertext" << ciphertext << endl;

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
	//cout << "key: " << encoded << endl << endl;

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

	string tag = encoded;

	string data = timestamphex + ciphertext + tag;

	//cout << "Data " << data << endl;

	/*********************************\
	\*********************************/

	std::ofstream outfile("..\\..\\ciphertext.txt");
	outfile << data;
	outfile.close();
	//cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC;
	
	AutoSeededRandomPool rnd;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rnd, 3072);

	std::ifstream ifs("..\\..\\publickey.txt");
	std::string content_public((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));

	RSA::PublicKey publickey;
	StringSource f2(content_public, true, new HexDecoder);
	publickey.Load(f2);

	////////////////////////////////////////////////
	// Encryption
	RSAES_OAEP_SHA_Encryptor e(publickey);

	string encrypted_symmetric_key1;
	//Encryption is Done over Here
	StringSource(symmetric_key, true,
		new PK_EncryptorFilter(rnd, e,
		new StringSink(encrypted_symmetric_key1)
		) // PK_EncryptorFilter
		); // StringSource



	//cout << "\nCipher text has been generated :" << encrypted_symmetric_key1 << endl;

	string encrypted_symmetric_key;
	StringSource(encrypted_symmetric_key1, true,
		new HexEncoder(
		new StringSink(encrypted_symmetric_key)
		) // HexEncoder
		); // StringSource
	//cout << "\nencrypted symmetric key encoded in base16 (hexadecimal) format :" << encrypted_symmetric_key << endl;

	std::ofstream outfile1("..\\..\\encrypted_symmetric_key.txt");
	outfile1 << encrypted_symmetric_key;
	outfile1.close();
	cout << "Ciphertext Generated using AES_CBC with IV=0 and HMAC_SHA2 scheme " << endl;
	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC << endl;
	_getch();
	return 0;
}
void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{

	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}
void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}