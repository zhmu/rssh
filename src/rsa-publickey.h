#ifndef RSSH_RSA_PUBLICKEY_H
#define RSSH_RSA_PUBLICKEY_H

#include <stdint.h>
#include <cstddef>
#include "cryptopp/integer.h"

namespace RSSH {

class RSAPublicKey {
public:
	RSAPublicKey(const uint8_t* buffer, size_t len);
	bool Verify(const uint8_t* signature, size_t sig_len, const uint8_t* data, size_t data_len) const;

private:
	CryptoPP::Integer m_E, m_N;
};

} // namespace RSSH

#endif /* RSSH_RSA_PUBLICKEY_H */
