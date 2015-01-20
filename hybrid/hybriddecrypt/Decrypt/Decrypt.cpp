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
	clock_t tStart = clock();
	string key, decodediv, cipher, recovered, new_hmackey;
	string iv = "00000000000000000000000000000000";

	StringSource(iv, true,
		new HexDecoder(
		new StringSink(decodediv)
		) // HexEncoder
		); // StringSource
	//cout << “iv converted from base16 to byte” << decodediv << endl;

	std::ifstream ifs1("..\\..\\encrypted_symmetric_key.txt");
	std::string content_sym_key((std::istreambuf_iterator<char>(ifs1)),
		(std::istreambuf_iterator<char>()));
	//cout << "symm key read from file :" << content_sym_key << endl;

	string decoded_symm_key;
	StringSource(content_sym_key, true,
		new HexDecoder(
		new StringSink(decoded_symm_key)
		) // HexEncoder
		); // StringSource
	//cout << "\nsymmetric key converted from base16 to byte" << decoded_symm_key << endl;


	AutoSeededRandomPool rnd;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rnd, 3072);

	std::ifstream ifs("..\\..\\secretkey.txt");
	std::string content_secret((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));

	RSA::PrivateKey secretkey;
	StringSource f2(content_secret, true, new HexDecoder);
	secretkey.Load(f2);
	

	////////////////////////////////////////////////
	// Decryption
	RSAES_OAEP_SHA_Decryptor d(secretkey);
	string decrypted_symmetric_key;
	StringSource ss2(decoded_symm_key, true,
		new PK_DecryptorFilter(rnd, d,
		new StringSink(decrypted_symmetric_key)
		) // PK_DecryptorFilter
		); // StringSource

	//cout << "\nsymmetric key :" << decrypted_symmetric_key << endl;
	string content = decrypted_symmetric_key;
	
	string hmackey = content.substr(32, 64);
	//cout << "hmackey " << hmackey << endl;
	content.erase(32, 64);
	//cout << "key  " << content << endl;
	
	StringSource(content, true,
		new HexDecoder(
		new StringSink(key)
		) // HexEncoder
		); // StringSource
	//cout << "key converted from base16 to byte" << key << endl;
	
	StringSource(hmackey, true,
		new HexDecoder(
		new StringSink(new_hmackey)
		) // HexEncoder
		); // StringSource
	//cout << "key converted from base16 to byte" << new_hmackey << endl;
	
	int len = hmackey.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = hmackey.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), 0, 16);
		newString.push_back(chr);
	}
	//cout << "hex to ascii output" << newString << endl;
	
	std::ifstream ifs2("..\\..\\ciphertext.txt");
	std::string data_content((std::istreambuf_iterator<char>(ifs2)),
		(std::istreambuf_iterator<char>()));
	//cout << "hmac key" << hmackey << endl;
	//cout << "datacontent " << data_content << endl;
	//cout << endl;
	std::string tag, ct, timestamp;
	timestamp = data_content.substr(0, 50);
	//cout << "timestamp" << timestamp << endl;
	//cout << endl;
	data_content.erase(0, 50);
	//cout << "datacontent without timestamp " << data_content << endl;
	//cout << "length of data content " << data_content.length() << endl;
	//cout << endl;
	tag = data_content.substr(data_content.size() - 64, data_content.size() - 1);
	//cout << "tag" << tag << endl;
	//cout << "length of tag " << tag.length() << endl;
	//cout << endl;
	ct = data_content.substr(0, data_content.size() - 64);
	//cout << "ciphertext" << ct << endl;
	//cout << "length of ciphertext " << ct.length() << endl;
	//cout << endl;
	string ct_ts = ct + timestamp;
	//cout << "ct + timestamp " << ct_ts << endl;
	//cout << endl;

	string decodedtimestamp;
	StringSource(timestamp, true,
		new HexDecoder(
		new StringSink(decodedtimestamp)
		) // HexEncoder
		); // StringSource
	//cout << "Timestamp" << decodedtimestamp << endl << endl;

	//cout << "Received HMAC : " << tag << endl << endl;

	byte* b = (byte*)newString.c_str();

	//cout << "value of b " << b << endl << endl;
	//cout << "hmac keyy" << hmackey << endl << endl;
	string mac, encoded;
	try
	{
		HMAC< SHA256 > hmac(b, sizeof(b));
		//cout << "Sizes  " << sizeof(b) << endl << endl;
		//cout << "HMACKEY " << b << endl << endl;
		StringSource(ct_ts, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
		//cout << "Calculated HMAC " << mac << endl << endl;

		string hex_mac;
		StringSource(mac, true,
			new HexEncoder(
			new StringSink(hex_mac)
			) // HexEncoder
			); // StringSource
		//cout << "MAC in hex : " << hex_mac << endl << endl;

	}
	catch (const CryptoPP::Exception& ex)
	{
		cerr << ex.what() << endl;
		exit(1);
	}
	try
	{
		HMAC< SHA256 > hmac(b, sizeof(b));
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		// Tamper with message
		// plain[0] ^= 0x01;

		// Tamper with MAC
		// mac[0] ^= 0x01;

		StringSource(ct_ts + mac, true,
			new HashVerificationFilter(hmac, NULL, flags)
			); // StringSource

		cout << "Message verified" << endl << endl;
	}
	catch (const CryptoPP::Exception& e2)
	{
		cerr << e2.what() << endl;
		exit(1);
	}


	StringSource(ct, true,
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
		//cout << "\nDecrypted plain text :" << recovered << endl;

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
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

	cout << "Decryption Done using AES_CBC and IV=0!!" << endl << endl;
	cout << "Time taken: " << (double)(clock() - tStart) / CLOCKS_PER_SEC<<endl;
	
	
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