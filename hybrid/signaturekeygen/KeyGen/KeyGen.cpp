// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe
#include "stdafx.h"
#include <conio.h>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::hex;

#include <sstream>

#include "..\..\..\SecBlock.h"
using CryptoPP::SecByteBlock;

#include "..\..\..\sha.h"
using CryptoPP::SHA1;


#include <string>
using std::string;
using namespace std;

#include "..\..\..\rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;

#include "..\..\..\pssr.h"
using CryptoPP::PSS;

#include <stdexcept>
using std::runtime_error;

#include "..\..\..\queue.h"
using CryptoPP::ByteQueue;

#include "..\..\..\files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "..\..\..\dsa.h"
using CryptoPP::DSA;

#include <bitset>
using std::bitset;

#include "..\..\..\base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "..\..\..\cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "..\..\..\osrng.h"
using CryptoPP::AutoSeededRandomPool;


#include "..\..\..\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "..\..\..\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);

int main(int argc, char** argv)
{
	std::ios_base::sync_with_stdio(false);

	// http://www.cryptopp.com/docs/ref/class_auto_seeded_random_pool.html
	AutoSeededRandomPool rnd;

	try
	{
		// http://www.cryptopp.com/docs/ref/rsa_8h.html
		RSA::PrivateKey rsaPrivate;
		rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

		RSA::PublicKey rsaPublic(rsaPrivate);

		//cout << "outfile encoded :" << encoded << endl;
		SaveHexPrivateKey("..\\..\\signsecretkey.txt", rsaPrivate);
		SaveHexPublicKey("..\\..\\signpublickey.txt", rsaPublic);
		
		std::ifstream ifs1("..\\..\\signpublickey.txt");
		std::string content_public((std::istreambuf_iterator<char>(ifs1)),
			(std::istreambuf_iterator<char>()));
		//cout << "content_public" << content_public << endl;

		string myString = "ivp216@nyu.edu";
		istringstream buffer(myString);
		uint64_t value;
		buffer >> std::hex >> value;
		//cout << "identity" << value << endl;

		std::stringstream sstm;
		sstm << content_public << value;
		string result = sstm.str();
		//cout << "message" << result;
		
		std::ofstream out("..\\..\\message.txt");
		out << result;
		out.close();


		cout << "Successfully generated and saved DSA keys" << endl;
	
	
	}

	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch (std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}
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

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
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

void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveHex(filename, queue);
}

void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveHex(filename, queue);
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
	HexEncoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}