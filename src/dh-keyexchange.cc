#include "dh-keyexchange.h"
#include "callback.h"
#include "exception.h"
#include "keys.h"
#include "numbers.h"
#include "random.h"
#include "rsa-publickey.h"
#include "trace.h"
#include "transport.h"

#include "cryptopp/base64.h"
#include "cryptopp/dh.h"
#include "cryptopp/nbtheory.h"

namespace RSSH {

DHKeyExchange::DHKeyExchange(Transport& transport, const char* algorithm)
	: m_Transport(transport), m_Keys(NULL)
{
	if (strcmp(algorithm, "diffie-hellman-group14-sha1") == 0) {
		// [RFC3526, 3]
		m_P = CryptoPP::Integer("0x"
		 "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		 "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		 "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		 "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		 "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		 "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		 "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		 "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
		 "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
		 "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
		 "15728E5A8AACAA68FFFFFFFFFFFFFFFF");
		m_G = CryptoPP::Integer("0x2");
	} else
		throw Exception(Exception::C_DH_Unrecognized_Algorithm);
}

DHKeyExchange::~DHKeyExchange()
{
	delete m_Keys;
}

void DHKeyExchange::SendExchange()
{ 
	// Values from RFC3526, 3. 2048-bit MODP Group
	CryptoPP::DH dh;
	dh.AccessGroupParameters().Initialize(m_P, m_G);

	// [SSH-TRANS] 8, step 1: pick 1 < x < q, generate 'e = g^x mod p'
	{
		CryptoPP::Integer q = dh.GetGroupParameters().GetSubgroupOrder();
		m_X = CryptoPP::Integer(Random::GetInstance().GetRng(), CryptoPP::Integer(1), q);
		m_E = CryptoPP::ModularExponentiation(m_G, m_X, m_P);
	}

	// Send e to S
	{
		Buffer b;
		b << static_cast<uint32_t>(0); // len
		b << static_cast<uint8_t>(0); // padding len
		b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_KEXDH_INIT);
		b << m_E;
		m_Transport.TransmitPacket(b);
	}
}

void DHKeyExchange::OnReply(Buffer& buffer)
{
	std::string publickey, signature;
	CryptoPP::Integer val_F;
	buffer >> publickey >> val_F >> signature;

	// [SSH-TRANS, 8] calculate K = f^x mod p
	CryptoPP::Integer val_K = CryptoPP::ModularExponentiation(val_F, m_X, m_P);

	// [SSH-TRANS, 8] calculate 'H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)'
	unsigned char hash_H[CryptoPP::SHA::DIGESTSIZE];
	{
		Buffer h;
		h << std::string(Numbers::ourGreeter); // V_C
		h << std::string(m_Transport.GetGreeter()); // V_S
		h.PutData((const uint8_t*)m_Transport.GetMyKexPayload(), m_Transport.GetMyKexPayloadLength()); // I_C
		h.PutData((const uint8_t*)m_Transport.GetServerKexPayload(), m_Transport.GetServerKexPayloadLength()); // I_S
		h << publickey; // K_S
		h << m_E; // e
		h << val_F; // f
		h << val_K; // k

		// Compute hash_H = hash(h)
		CryptoPP::SHA1 sha1;
		sha1.Update((const unsigned char*)h.GetReadPointer(), h.GetAvailableBytes());
		sha1.Final(hash_H);
	}

	// [SSH-TRANS, 8] Verify that K_S really is the host key for S
	{
		/*
		 * Even if not in the SSH specification, OpenSSH seems to
		 * take the SHA256 hash of the public key and Base64 encode
		 * it as an identifier. This seems sensible enough, so we
		 * just do the same.
		 */
		std::string pk_hash_base64;
		{
			uint8_t pk_hash[CryptoPP::SHA256::DIGESTSIZE];
			CryptoPP::SHA256 sha256;
			sha256.Update((const uint8_t*)publickey.c_str(), publickey.size());
			sha256.Final(pk_hash);

			CryptoPP::Base64Encoder encoder;
			encoder.Attach(new CryptoPP::StringSink(pk_hash_base64));
			encoder.Put(pk_hash, sizeof(pk_hash));
			encoder.MessageEnd();
		}
		Trace::Info("public key signature: %s", pk_hash_base64.c_str());

		if (!m_Transport.GetCallback().OnVerifyHostKeySignature(pk_hash_base64))
			throw Exception(Exception::C_HostKey_Signature_Rejected);
	}

	// [SSH-TRANS, 8] Verify the RSA signature
	{
		RSAPublicKey pk((const uint8_t*)publickey.c_str(), publickey.size());
		if (!pk.Verify((const uint8_t*)signature.c_str(), signature.size(), hash_H, sizeof(hash_H)))
			throw Exception(Exception::C_PK_Signature_Mismatch);

	}

	// [SSH-TRANS, 7.2] Derive keys
	if (m_Transport.SessionIdentifier().empty()) {
		// First exchange hash H is the session identifier
		m_Transport.SessionIdentifier() = std::string((const char*)hash_H, sizeof(hash_H));
	}

	m_Keys = new Keys(CryptoPP::SHA::DIGESTSIZE);
	m_Keys->Derive<CryptoPP::SHA>(val_K, hash_H, m_Transport.SessionIdentifier());
}

} // namespace RSSH
