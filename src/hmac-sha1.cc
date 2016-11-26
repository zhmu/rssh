#include "hmac-sha1.h"

namespace RSSH {

HMAC_SHA1::HMAC_SHA1(const uint8_t* key, size_t keyLen)
{
	m_HMAC = new CryptoPP::HMAC< CryptoPP::SHA >(key, keyLen);
}

HMAC_SHA1::~HMAC_SHA1()
{
	delete m_HMAC;
}

void HMAC_SHA1::Calculate(const uint8_t* buffer, size_t len, uint32_t sequenceNumber, uint8_t* out)
{
	uint8_t seq_no[4] = {
		static_cast<uint8_t>((sequenceNumber >> 24) & 0xff),
		static_cast<uint8_t>((sequenceNumber >> 16) & 0xff),
		static_cast<uint8_t>((sequenceNumber >> 8) & 0xff),
		static_cast<uint8_t>(sequenceNumber & 0xff)
	};

	m_HMAC->Restart();
	m_HMAC->Update(seq_no, 4);
	m_HMAC->Update(buffer, len);
	m_HMAC->Final(out);
}

bool HMAC_SHA1::Verify(const uint8_t* buffer, size_t len, uint32_t sequenceNumber, const uint8_t* hmac)
{
	uint8_t out[20]; // XXX
	Calculate(buffer, len, sequenceNumber, out);
	return memcmp(hmac, out, 20) == 0;
}

size_t HMAC_SHA1::GetLength() const
{
	return m_HMAC->DigestSize();
}

} // namespace RSSH
