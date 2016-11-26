#include "rsa-publickey.h"
#include "buffer.h"
#include "exception.h"
#include "trace.h"

#include "cryptopp/rsa.h"

namespace RSSH {

RSAPublicKey::RSAPublicKey(const uint8_t* buffer, size_t len)
{
	Buffer b(buffer, len);
	std::string pk_type;
	b >> pk_type;
	if (pk_type != "ssh-rsa")
		throw Exception(Exception::C_PK_Unrecognized_Algorithm);

	b >> m_E >> m_N;
}

bool RSAPublicKey::Verify(const uint8_t* signature, size_t sig_len, const uint8_t* data, size_t data_len) const
{
	// Parse signature
	Buffer b(signature, sig_len);
	std::string sig_type, sig_data;
	b >> sig_type;
	if (sig_type != "ssh-rsa")
		throw Exception(Exception::C_PK_Unrecognized_Algorithm);
	b >> sig_data;

	CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(m_N, m_E);
	return verifier.VerifyMessage(data, data_len, (const unsigned char*)sig_data.c_str(), sig_data.size());
}

} // namespace RSSH
