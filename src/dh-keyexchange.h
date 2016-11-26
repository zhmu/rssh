#ifndef RSSH_DH_KEYEXCHANGE_H
#define RSSH_DH_KEYEXCHANGE_H

#include "cryptopp/integer.h"
#include "socket.h"

namespace RSSH {

class Buffer;
class Keys;
class Transport;

class DHKeyExchange {
public:
	DHKeyExchange(Transport& transport, const char* algorithm);
	~DHKeyExchange();

	void SendExchange();
	void OnReply(Buffer& buffer);

	Keys* GetKeys() const {
		return m_Keys;
	}

private:
	//! Transport layer we belong to
	Transport& m_Transport;

	//! Diffie-Hellman prime and generator values
	CryptoPP::Integer m_P, m_G;

	//
	CryptoPP::Integer m_E;

	//! Picked random number, 1 < m_X < m_G
	CryptoPP::Integer m_X;

	//! Derived keys
	Keys* m_Keys;
};

} // namespace RSSH

#endif /* RSSH_DH_KEYEXCHANGE_H */
