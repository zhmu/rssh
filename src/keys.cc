#include "keys.h"
#include <string.h>

namespace {

} // unnamed namespace

namespace RSSH {

Keys::Keys(size_t keySize)
	: m_KeySize(keySize)
{
	m_InitialIV_C2S = new uint8_t[keySize];
	m_InitialIV_S2C = new uint8_t[keySize];
	m_EncryptionKey_C2S = new uint8_t[keySize];
	m_EncryptionKey_S2C = new uint8_t[keySize];
	m_IntegrityKey_C2S = new uint8_t[keySize];
	m_IntegrityKey_S2C = new uint8_t[keySize];

	Clear();
}

void Keys::Clear()
{
	memset(m_InitialIV_C2S, 0, m_KeySize);
	memset(m_InitialIV_S2C, 0, m_KeySize);
	memset(m_EncryptionKey_S2C, 0, m_KeySize);
	memset(m_EncryptionKey_C2S, 0, m_KeySize);
	memset(m_IntegrityKey_C2S, 0, m_KeySize);
	memset(m_IntegrityKey_S2C, 0, m_KeySize);
}

Keys::~Keys()
{
	Clear();
	delete[] m_IntegrityKey_S2C;
	delete[] m_IntegrityKey_C2S;
	delete[] m_EncryptionKey_S2C;
	delete[] m_EncryptionKey_C2S;
	delete[] m_InitialIV_S2C;
	delete[] m_InitialIV_C2S;
}

} // namespace RSSH
