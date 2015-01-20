#include "stdafx.h"
#include <conio.h>
#include <fstream>  
using namespace std;
#include "..\..\..\integer.h"
using CryptoPP::Integer;

#include "..\..\..\files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "..\..\..\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "..\..\..\pssr.h"
using CryptoPP::PSSR;

#include "..\..\..\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;


#include "..\..\..\cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "..\..\..\rsa.h"
using CryptoPP::RSA;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::InvertibleRSAFunction;

#include "..\..\..\rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASS;
using CryptoPP::RSA;

#include "..\..\..\filters.h"
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "..\..\..\cryptlib.h"
using CryptoPP::Exception;

#include "..\..\..\sha.h"
using CryptoPP::SHA1;

#include <string>
using std::string;

#include "..\..\..\queue.h"
using CryptoPP::ByteQueue;

#include <iostream>
using std::cout;
using std::endl;
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
	try {

		////////////////////////////////////////////////
		// Generate keys
		AutoSeededRandomPool rng;

		InvertibleRSAFunction parameters;
		parameters.GenerateRandomWithKeySize(rng, 1024);
		RSA::PrivateKey r1;

		// Loading

		std::ifstream ifs1("..\\..\\signsecretkey.txt");
		std::string content_secret((std::istreambuf_iterator<char>(ifs1)),
			(std::istreambuf_iterator<char>()));
	
		RSA::PrivateKey secretkey;
		StringSource f2(content_secret, true, new HexDecoder);
		secretkey.Load(f2);

		std::ifstream ifs2("..\\..\\message.txt");
		std::string content_message((std::istreambuf_iterator<char>(ifs2)),
			(std::istreambuf_iterator<char>()));

		string message = content_message, signature, recovered;

		////////////////////////////////////////////////
		// Sign and Encode
		RSASS<PSSR, SHA1>::Signer signer(secretkey);

		StringSource(message, true,
			new SignerFilter(rng, signer,
			new StringSink(signature),
			true // putMessage
			) // SignerFilter
			); // StringSource
		//cout << "outfile" << signature << endl;
		string encoded;
		encoded.clear();
		StringSource(signature, true,
			new HexEncoder(
			new StringSink(encoded)
			) // HexEncoder
			); // StringSource
		//cout << "outfile encoded :" << encoded << endl;
		cout << "Signature generated.." << endl;
		std::ofstream out("..\\..\\signature.txt");
		out << encoded;
		out.close();
		
	} // try

	catch (CryptoPP::Exception&e)
	{
		std::cerr << "Error: " << e.what() << endl;
	}
	_getch();
	return 0;
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
void SaveKey(const RSA::PublicKey& PublicKey, const string& filename)
{
	// DER Encode Key - X.509 key format
	PublicKey.Save(
		FileSink(filename.c_str(), true /*binary*/).Ref()
		);
}

void SaveKey(const RSA::PrivateKey& PrivateKey, const string& filename)
{
	// DER Encode Key - PKCS #8 key format
	PrivateKey.Save(
		FileSink(filename.c_str(), true /*binary*/).Ref()
		);
}

void LoadKey(const string& filename, RSA::PublicKey& PublicKey)
{
	// DER Encode Key - X.509 key format
	PublicKey.Load(
		FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref()
		);
}

void LoadKey(const string& filename, RSA::PrivateKey& PrivateKey)
{
	// DER Encode Key - PKCS #8 key format
	PrivateKey.Load(
		FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref()
		);
}

void PrintPrivateKey(const RSA::PrivateKey& key)
{
	cout << "n: " << key.GetModulus() << endl;

	cout << "d: " << key.GetPrivateExponent() << endl;
	cout << "e: " << key.GetPublicExponent() << endl;

	cout << "p: " << key.GetPrime1() << endl;
	cout << "q: " << key.GetPrime2() << endl;
}

void PrintPublicKey(const RSA::PublicKey& key)
{
	cout << "n: " << key.GetModulus() << endl;
	cout << "e: " << key.GetPublicExponent() << endl;
}

