#ifndef RSSH_SESSION_H
#define RSSH_SESSION_H

#include "cryptopp/osrng.h"

namespace RSSH {

class Random {
public:
	static Random& GetInstance();

	CryptoPP::AutoSeededRandomPool& GetRng() {
		return m_Rng;
	}

	void Generate(unsigned char* buffer, size_t len) {
		m_Rng.GenerateBlock(buffer, len);
	}

private:
	CryptoPP::AutoSeededRandomPool m_Rng;
};

} // namespace RSSH

#endif /* RSSH_SESSION_H */
