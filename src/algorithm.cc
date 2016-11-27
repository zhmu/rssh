#include "algorithm.h"
#include "cipher-factory.h"
#include "exception.h"
#include "hmac-sha1.h"
#include "icipher.h"
#include "keys.h"

namespace RSSH {

Algorithm::Algorithm(const char* cipher_c2s, const char* cipher_s2c, const char* hmac_c2s, const char* hmac_s2c, Keys& keys)
{
	m_Cipher_C2S = CipherFactory::Create(cipher_c2s, true, keys.GetInitialIV_C2S(), keys.GetEncryptionKey_C2S());
	m_Cipher_S2C = CipherFactory::Create(cipher_s2c, false, keys.GetInitialIV_S2C(), keys.GetEncryptionKey_S2C());
	m_MAC_C2S = new HMAC_SHA1(keys.GetIntegrityKey_C2S(), keys.GetKeySize());
	m_MAC_S2C = new HMAC_SHA1(keys.GetIntegrityKey_S2C(), keys.GetKeySize());
}

Algorithm::~Algorithm()
{
	delete m_MAC_C2S;
	delete m_MAC_S2C;
	delete m_Cipher_S2C;
	delete m_Cipher_C2S;
}

void Algorithm::Encrypt_C2S(uint8_t* buffer, size_t len)
{
	m_Cipher_C2S->Process(buffer, len);
}

void Algorithm::Decrypt_S2C(uint8_t* buffer, size_t len)
{
	m_Cipher_S2C->Process(buffer, len);
}

void Algorithm::PerformHMAC_C2S(Buffer& buffer, uint32_t sequenceNumber)
{
	m_MAC_C2S->Calculate(buffer.GetReadPointer(), buffer.GetAvailableBytes(), sequenceNumber, buffer.GetWritePointer());
	buffer.SetWritePosition(buffer.GetWritePosition() + m_MAC_C2S->GetLength());
}

bool Algorithm::CheckHMAC_S2C(const uint8_t* buffer, size_t len, uint32_t sequenceNumber)
{
	return m_MAC_S2C->Verify(buffer, len, sequenceNumber, &buffer[len]);
}

size_t Algorithm::GetHMACSize_C2S() const
{
	return m_MAC_C2S->GetLength();
}

size_t Algorithm::GetHMACSize_S2C() const
{
	return m_MAC_S2C->GetLength();
}

size_t Algorithm::GetBlockSize_C2S() const
{
	return m_Cipher_C2S->GetBlockSize();
}

size_t Algorithm::GetBlockSize_S2C() const
{
	return m_Cipher_S2C->GetBlockSize();
}

} // namespace RSSH
