#ifndef RSSH_ALGORITHM_H
#define RSSH_ALGORITHM_H

#include <cstddef>
#include <stdint.h>

namespace RSSH {

class Buffer;
class Keys;
class ICipher;
class IHMAC;

class Algorithm {
public:
	Algorithm(const char* cipher_c2s, const char* cipher_s2c, const char* hmac_c2s, const char* hmac_s2c, Keys& keys);
	~Algorithm();

	void Encrypt_C2S(uint8_t* buffer, size_t len);
	void Decrypt_S2C(uint8_t* buffer, size_t len);
	void PerformHMAC_C2S(Buffer& buffer, uint32_t sequenceNumber);
	bool CheckHMAC_S2C(const uint8_t* buffer, size_t len, uint32_t sequenceNumber);

	size_t GetBlockSize_C2S() const;
	size_t GetBlockSize_S2C() const;
	size_t GetHMACSize_C2S() const;
	size_t GetHMACSize_S2C() const;

private:
	ICipher* m_Cipher_C2S;
	ICipher* m_Cipher_S2C;
	IHMAC* m_MAC_C2S;
	IHMAC* m_MAC_S2C;
};

} // namespace RSSH

#endif /* RSSH_ALGORITHM_H */
