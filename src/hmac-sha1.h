#ifndef RSSH_HMAC_SHA1_H
#define RSSH_HMAC_SHA1_H

#include <cstddef>
#include "ihmac.h"

#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"

namespace RSSH {

class HMAC_SHA1 : public IHMAC {
public:
	HMAC_SHA1(const uint8_t* key, size_t keyLeudo);
	virtual ~HMAC_SHA1();

	void Calculate(const uint8_t* buffer, size_t len, uint32_t sequenceNumber, uint8_t* out) override;
	bool Verify(const uint8_t* buffer, size_t len, uint32_t sequenceNumber, const uint8_t* hmac) override;
	size_t GetLength() const override;

private:
	CryptoPP::HMAC< CryptoPP::SHA >* m_HMAC;
};

} // namespace RSSH

#endif /* RSSH_HMAC_SHA1_H */
