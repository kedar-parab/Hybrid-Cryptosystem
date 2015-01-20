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
#include <time.h>
#include <iostream>
#include <string>
#include "..\..\..\modes.h"
#include "..\..\..\aes.h"
#include "..\..\..\filters.h"

void F_CBC_MAC(string decodediv)
{
	string key, cipher, recovered, recovered_timestamp;

	std::ifstream ifs("..\\..\\F_CBC_MAC_key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.
	//cout << "k1 + k2  " << content << endl;
	string k2 = content.substr(32, 64);
	//cout << "k2 " << k2 << endl;
	content.erase(32, 64);
	//cout << "k1  " << content << endl;

	StringSource(content, true,
		new HexDecoder(
		new StringSink(key)
		) // HexEncoder
		); // StringSource
	//cout << “key converted from base16 to byte” << key << endl;

	std::ifstream ifsp("..\\..\\F_CBC_MAC_ciphertext.txt");
	std::string contentp((std::istreambuf_iterator<char>(ifsp)),
		(std::istreambuf_iterator<char>()));
	string ciphertext = contentp;

	std::string tag, ct, timestamp;
	timestamp = ciphertext.substr(0, 64);
	//cout << "timestamp" << timestamp << endl;

	string ts;
	StringSource(timestamp, true,
		new HexDecoder(
		new StringSink(ts)
		) // HexEncoder
		); // StringSource
	//cout << "Timestamp : " << ts << endl;

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(ts, true,
			new StreamTransformationFilter(d,
			new StringSink(recovered_timestamp)
			) // StreamTransformationFilter
			); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)ts.data(), ts.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered_timestamp.data(), recovered_timestamp.size());
#endif

		cout << "Timestamp " << recovered_timestamp << endl;

	}
	catch (const CryptoPP::Exception& d)
	{
		cerr << d.what() << endl;
		exit(1);
	}

	ciphertext.erase(0, 64);
	tag = ciphertext.substr(ciphertext.size() - 33, 32);
	cout << "Received F_CBC_MAC tag : " << tag << endl;
	string ciphertextnew = ciphertext.substr(0, ciphertext.size() - 33);
	//cout << "ciphertext" << ciphertextnew << endl;

	string k2decoded;
	string last_block = ciphertextnew.substr(ciphertextnew.length() - 30, ciphertextnew.length());
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
	string tagverify;
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s1(newString, true,
		new StreamTransformationFilter(e1,
		new StringSink(tagverify)
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

	string verified_tag;
	StringSource(tagverify, true,
		new HexEncoder(
		new StringSink(verified_tag)
		) // HexEncoder
		); // StringSource

	cout << "tag generated from the ciphertext : " << verified_tag << endl;

	if (tag == verified_tag)
	{
		cout << "Tag verified" << endl;

		StringSource(ciphertextnew, true,
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
			filter.Put((const byte*)cipher.data(), cipher.size());
			filter.MessageEnd();

			const size_t ret = filter.MaxRetrievable();
			recovered.resize(ret);
			filter.Get((byte*)recovered.data(), recovered.size());
#endif

			std::ofstream outfile("..\\..\\F_CBC_MAC_decryptedplaintext.txt");
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
	}
	else
	{
		cout << "Tags are not the same." << endl;
	}
	
}

void HMAC_SHA2(string decodediv)
{
	string key, cipher, recovered, new_hmackey;
	std::ifstream ifs1("..\\..\\HMAC_SHA2_key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs1)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.
	//cout << "encryption key" << content<<endl;
	string hmackey = content.substr(32, 64);
	//cout << "hmackey " << hmackey << endl;
	content.erase(32, 64);
	//cout << "key  " << content << endl;

	StringSource(content, true,
		new HexDecoder(
		new StringSink(key)
		) // HexEncoder
		); // StringSource
	//cout << “key converted from base16 to byte” << key << endl;

	StringSource(hmackey, true,
		new HexDecoder(
		new StringSink(new_hmackey)
		) // HexEncoder
		); // StringSource
	//cout << “key converted from base16 to byte” << newhmackey << endl;

	int len = hmackey.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = hmackey.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), 0, 16);
		newString.push_back(chr);
	}
	//cout << "hex to ascii output" << newString << endl;

	std::ifstream ifs2("..\\..\\HMAC_SHA2_ciphertext.txt");
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
	cout << "Timestamp " << decodedtimestamp << endl;

	cout << "Received HMAC tag: " << tag << endl;

	byte* b = (byte*)newString.c_str();

	//cout << "value of b " << b << endl << endl;
	//cout << "hmac keyy" << hmackey << endl << endl;
	string mac, encoded, hex_mac;
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

		
		StringSource(mac, true,
			new HexEncoder(
			new StringSink(hex_mac)
			) // HexEncoder
			); // StringSource
		cout << "tag generated from ciphertext: " << hex_mac << endl;

	}
	catch (const CryptoPP::Exception& ex)
	{
		cerr << ex.what() << endl;
		exit(1);
	}
	
	if (tag == hex_mac)
	{
		cout << "Tag verified. "<<endl;

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

#if 0
			StreamTransformationFilter filter(d);
			filter.Put((const byte*)cipher.data(), cipher.size());
			filter.MessageEnd();

			const size_t ret = filter.MaxRetrievable();
			recovered.resize(ret);
			filter.Get((byte*)recovered.data(), recovered.size());
#endif

			std::ofstream outfile("..\\..\\HMAC_SHA2_decryptedplaintext.txt");
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
	}
	else
	{
		cout << "tag are not the same." << endl;
	}
}
void PRF_MAC(string decodediv)
{
	string key, cipher, recovered, key1, recovered_timestamp;
	
	std::ifstream ifs("..\\..\\PRF_MAC_key.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));
	//reading the file “key.txt”.

	//cout << "k1 + k2  " << content << endl;
	string k2 = content.substr(32, 64);
	//cout << "k2 " << k2 << endl;
	content.erase(32, 64);
	//cout << "k1  " << content << endl;

	std::ifstream ifs1("..\\..\\PRF_MAC_ciphertext.txt");
	std::string cipher_content((std::istreambuf_iterator<char>(ifs1)),
		(std::istreambuf_iterator<char>()));
	//reading the file “encryptedplaintext.txt”
	//cout << "Cipher content original: " << cipher_content << endl;


	StringSource(k2, true,
		new HexDecoder(
		new StringSink(key)
		) // HexEncoder
		); // StringSource
	//cout << "key converted from base16 to byte" << key << endl;

	StringSource(content, true,
		new HexDecoder(
		new StringSink(key1)
		) // HexEncoder
		); // StringSource
	//cout << "key1 converted from base16 to byte" << key1 << endl;

	std::string tag, timestamp;
	timestamp = cipher_content.substr(0, 64);
	//cout << "timestamp before " << timestamp << endl << timestamp.length() << endl;

	string ts;
	StringSource(timestamp, true,
		new HexDecoder(
		new StringSink(ts)
		) // HexEncoder
		); // StringSource
	//cout << "Timestamp : " << ts << endl;

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV((byte*)key1.c_str(), key1.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(ts, true,
			new StreamTransformationFilter(d,
			new StringSink(recovered_timestamp)
			) // StreamTransformationFilter
			); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)ts.data(), ts.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered_timestamp.data(), recovered_timestamp.size());
#endif

		cout << "Timestamp " << recovered_timestamp << endl;

	}
	catch (const CryptoPP::Exception& d)
	{
		cerr << d.what() << endl;
		exit(1);
	}

	cipher_content.erase(0, 64);
	//cout << "cipher content without timestamp " << cipher_content << endl << "length " << cipher_content.length() << endl;
	int n = cipher_content.length() / 32;
	int y, z;
	y = (n - 1) / 2;
	z = y + 1;
	tag = cipher_content.substr(cipher_content.size() - (z * 32), cipher_content.size());
	cout << "Received PRF_MAC tag " << tag << endl;
	//cout << "length " << tag.length() << endl;
	cipher_content.erase(cipher_content.size() - (z * 32), cipher_content.size());
	//cout << "cipher content without tag " << cipher_content << endl << "length " << cipher_content.length() << endl;
	string ct = cipher_content;
	//cout << "ct " << ct << endl << endl;

	string ciphertext;
	StringSource(ct, true,
		new HexDecoder(
		new StringSink(cipher)
		) // HexEncoder
		); // StringSource

	string mac;
	StringSource(tag, true,
		new HexDecoder(
		new StringSink(mac)
		) // HexEncoder
		); // StringSource

	//cout << "Original tag: " << mac << endl;

	string newmac,newtag;
	try
	{
		CBC_Mode< AES> ::Encryption e;
		e.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)decodediv.c_str());


		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(e,
			new StringSink(newmac)
			) // StreamTransformationFilter
			); // StringSource
		
		StringSource(newmac, true,
			new HexEncoder(
			new StringSink(newtag)
			) // HexEncoder
			); // StringSource
		cout << "Tag generated from ciphertext: " << newtag << endl;

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)newmac.data(), newmac.size());
#endif

	}

	catch (const CryptoPP::Exception& d)
	{
		cerr << d.what() << endl;
		exit(1);
	}
	
	if (tag == newtag)
	{
		cout << "Tag verified" << endl;
		string plaintext;

	try
	{
		CBC_Mode< AES >::Decryption d1;
		d1.SetKeyWithIV((byte*)key1.c_str(), key1.size(), (byte*)decodediv.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s1(cipher, true,
			new StreamTransformationFilter(d1,
			new StringSink(plaintext)
			) // StreamTransformationFilter
			); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)plaintext.data(), plaintext.size());
#endif

		std::ofstream outfile("..\\..\\PRF_MAC_decryptedplaintext.txt");
		outfile << plaintext;
		outfile.close();
		//writing plaintext in the text file “decryptedplaintext.txt”.

	}

	catch (const CryptoPP::Exception& d1)
	{
		cerr << d1.what() << endl;
		exit(1);
	}


	cout << "Decryption Done using AES_CBC and IV=0!!" << endl;
	}
		else
		{
			cout << "Tags not verified";
		}
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