#ifndef RSSH_IHMAC_H
#define RSSH_IHMAC_H

#include <cstddef>
#include <stdint.h>

namespace RSSH {

class IHMAC {
public:
	virtual ~IHMAC() { }

	virtual void Calculate(const uint8_t* buffer, size_t len, uint32_t sequenceNumber, uint8_t* out) = 0;
	virtual bool Verify(const uint8_t* buffer, size_t len, uint32_t sequenceNumber, const uint8_t* hmac) = 0;
	virtual size_t GetLength() const = 0;
};

} // namespace RSSH

#endif /* RSSH_IHMAC_H */
