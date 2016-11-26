#ifndef RSSH_CIPHER_AES_H
#define RSSH_CIPHER_AES_H

#include "icipher.h"

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

namespace RSSH {

template<class T> class Cipher_AES : public ICipher {
public:
	Cipher_AES(const uint8_t* iv, const uint8_t* key, size_t keyLength);
	virtual ~Cipher_AES();
	void Process(uint8_t* buffer, size_t len) override;
	size_t GetBlockSize() const override;

private:
	T* m_AES;
};

template<class T> Cipher_AES<T>::Cipher_AES(const uint8_t* iv, const uint8_t* key, size_t keyLength)
{
	m_AES = new T;
	m_AES->SetKeyWithIV(key, 16 /* XXX keyLength */, iv);
}

template<class T> Cipher_AES<T>::~Cipher_AES()
{
	delete m_AES;
}

template<class T> void Cipher_AES<T>::Process(uint8_t* buffer, size_t len)
{
	m_AES->ProcessData(buffer, buffer, len);
}

template<class T> size_t Cipher_AES<T>::GetBlockSize() const
{
	return m_AES->MandatoryBlockSize();
}

typedef Cipher_AES<CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption> Cipher_AES_Encrypt;
typedef Cipher_AES<CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption> Cipher_AES_Decrypt;

} // namespace RSSH

#endif /* RSSH_CIPHER_AES_H */
