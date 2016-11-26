#ifndef RSSH_KEYS_H
#define RSSH_KEYS_H

#include "buffer.h"

namespace RSSH {

class Keys {
public:
	Keys(size_t keySize);
	~Keys();

	void Clear();

	template<class Hash> void Derive(const CryptoPP::Integer& k, const uint8_t* hash, const std::string& sessionId);

	const uint8_t* GetInitialIV_C2S() const {
		return m_InitialIV_C2S;
	}

	const uint8_t* GetInitialIV_S2C() const {
		return m_InitialIV_S2C;
	}

	const uint8_t* GetEncryptionKey_C2S() const {
		return m_EncryptionKey_C2S;
	}

	const uint8_t* GetEncryptionKey_S2C() const {
		return m_EncryptionKey_S2C;
	}

	const uint8_t* GetIntegrityKey_C2S() const {
		return m_IntegrityKey_C2S;
	}

	const uint8_t* GetIntegrityKey_S2C() const {
		return m_IntegrityKey_S2C;
	}

	size_t GetKeySize() const {
		return m_KeySize;
	}

private:
	size_t m_KeySize;

	uint8_t* m_InitialIV_C2S;
	uint8_t* m_InitialIV_S2C;
	uint8_t* m_EncryptionKey_C2S;
	uint8_t* m_EncryptionKey_S2C;
	uint8_t* m_IntegrityKey_C2S;
	uint8_t* m_IntegrityKey_S2C;
};

namespace {

template<class Hash> void DeriveKey(const CryptoPP::Integer& k, const uint8_t* hash, const uint8_t* p, const std::string& sessionId, uint8_t* output)
{
	// key = HASH(K || H || "..." || session_id)
	Buffer b;
	b << k;
	b.PutBytes(hash, Hash::DIGESTSIZE);
	b.PutBytes((const uint8_t*)p, 1);
	b.PutBytes((const uint8_t*)sessionId.c_str(), sessionId.size());

	// XXX deal with keysize != digestsize

	// Hash the value to obtain the key
	Hash h;
	h.Update((const unsigned char*)b.GetReadPointer(), b.GetAvailableBytes());
	h.Final(output);
}

} // unnamed namespace


template<class Hash> void Keys::Derive(const CryptoPP::Integer& k, const uint8_t* hash, const std::string& sessionId)
{
	DeriveKey<Hash>(k, hash, (const uint8_t*)"A", sessionId, m_InitialIV_C2S);
	DeriveKey<Hash>(k, hash, (const uint8_t*)"B", sessionId, m_InitialIV_S2C);
	DeriveKey<Hash>(k, hash, (const uint8_t*)"C", sessionId, m_EncryptionKey_C2S);
	DeriveKey<Hash>(k, hash, (const uint8_t*)"D", sessionId, m_EncryptionKey_S2C);
	DeriveKey<Hash>(k, hash, (const uint8_t*)"E", sessionId, m_IntegrityKey_C2S);
	DeriveKey<Hash>(k, hash, (const uint8_t*)"F", sessionId, m_IntegrityKey_S2C);
}

} // namespace RSSH

#endif /* RSSH_KEYS_H */
