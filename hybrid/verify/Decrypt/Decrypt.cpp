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


		//RSA::PublicKey r2;
		//LoadPublicKey("..\\..\\rsa-public.key", r2);
		
		////////////////////////////////////////////////
		// Setup

		std::ifstream ifs1("..\\..\\signpublickey.txt");
		std::string content_public((std::istreambuf_iterator<char>(ifs1)),
			(std::istreambuf_iterator<char>()));

		RSA::PublicKey publickey;
		StringSource f2(content_public, true, new HexDecoder);
		publickey.Load(f2);

		std::ifstream ifs2("..\\..\\message.txt");
		std::string content_message((std::istreambuf_iterator<char>(ifs2)),
			(std::istreambuf_iterator<char>()));

		string message = content_message, signature, recovered;
		
		std::ifstream in("..\\..\\signature.txt");
		std::string content((std::istreambuf_iterator<char>(in)),
			(std::istreambuf_iterator<char>()));
		//cout << "infile" << content << endl;
		string decoded;
		StringSource(content, true,
			new HexDecoder(
			new StringSink(decoded)
			) // HexEncoder
			); // StringSource
		//cout << "infile decoded :" << decoded << endl;
		////////////////////////////////////////////////
		// Verify and Recover
		RSASS<PSSR, SHA1>::Verifier verifier(publickey);

		StringSource(decoded, true,
			new SignatureVerificationFilter(
			verifier,
			new StringSink(recovered),
			SignatureVerificationFilter::THROW_EXCEPTION |
			SignatureVerificationFilter::PUT_MESSAGE
			) // SignatureVerificationFilter
			); // StringSource

		assert(message == recovered);
		string a = "YES";
		std::ofstream out("..\\..\\yesno_output.txt");
		out << a;
		out.close();
		cout << "Message verified"<< endl;

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

