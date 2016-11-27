#ifndef RSSH_CIPHER_AES_H
#define RSSH_CIPHER_AES_H

#include "icipher.h"

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

namespace RSSH {

template<class T, int KEYLENGTH> class Cipher_AES : public ICipher {
public:
	Cipher_AES(const uint8_t* iv, const uint8_t* key);
	virtual ~Cipher_AES();
	void Process(uint8_t* buffer, size_t len) override;
	size_t GetBlockSize() const override;

private:
	T* m_AES;
};

template<class T, int KEYLENGTH> Cipher_AES<T, KEYLENGTH>::Cipher_AES(const uint8_t* iv, const uint8_t* key)
{
	m_AES = new T;
	m_AES->SetKeyWithIV(key, KEYLENGTH, iv);
}

template<class T, int KEYLENGTH> Cipher_AES<T, KEYLENGTH>::~Cipher_AES()
{
	delete m_AES;
}

template<class T, int KEYLENGTH> void Cipher_AES<T, KEYLENGTH>::Process(uint8_t* buffer, size_t len)
{
	m_AES->ProcessData(buffer, buffer, len);
}

template<class T, int KEYLENGTH> size_t Cipher_AES<T, KEYLENGTH>::GetBlockSize() const
{
	return m_AES->MandatoryBlockSize();
}

typedef Cipher_AES<CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption, 16> Cipher_AES_128_CBC_Encrypt;
typedef Cipher_AES<CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption, 16> Cipher_AES_128_CBC_Decrypt;

} // namespace RSSH

#endif /* RSSH_CIPHER_AES_H */
