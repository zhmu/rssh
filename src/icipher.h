#ifndef RSSH_ICIPHER_H
#define RSSH_ICIPHER_H

#include <cstddef>
#include <stdint.h>

namespace RSSH {

class ICipher {
public:
	virtual ~ICipher() { }
	virtual void Process(uint8_t* buffer, size_t len) = 0;
	virtual size_t GetBlockSize() const = 0;
};

} // namespace RSSH

#endif /* RSSH_ICIPHER_H */
