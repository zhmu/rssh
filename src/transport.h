#ifndef RSSH_TRANSPORT_H
#define RSSH_TRANSPORT_H

#include "buffer.h"
#include "socket.h"

namespace RSSH {

class Algorithm;
class Callback;
class DHKeyExchange;

class Transport {
public:
	Transport(Callback& callback);
	~Transport();

	void Connect(const char* hostname, int port);
	void Process();

	/*! Transmit a given buffer
	 *
	 *  This will take care of padding, encryption and the MAC.
	 */
	void TransmitPacket(Buffer& buffer);

	const char* GetGreeter() const { return m_Greeter; }
	char* GetServerKexPayload() const { return m_ServerKexPayload; }
	size_t GetServerKexPayloadLength() const { return m_ServerKexPayloadLength; }
	char* GetMyKexPayload() const { return m_MyKexPayload; }
	size_t GetMyKexPayloadLength() const { return m_MyKexPayloadLength; }

	std::string& SessionIdentifier() { return m_SessionID; }
	void SendDisconnect();

	Callback& GetCallback() { return m_Callback; }

	//! Requests a service
	void RequestService(const char* serviceName);

private:
	void SendKexInitReply();
	void OnMessageKexInit(Buffer& buffer, size_t packetLength, size_t paddingLength);

	//! Socket in use
	Socket m_Socket;

	//! Buffer
	Buffer m_Buffer;

	Callback& m_Callback;

	static const size_t maxGreeterLength = 256; // [SSH-TRANS, 4.2] and +1 for \0
	char m_Greeter[maxGreeterLength];

	char* m_MyKexPayload;
	size_t m_MyKexPayloadLength;

	char* m_ServerKexPayload;
	size_t m_ServerKexPayloadLength;

	std::string m_SessionID;

	DHKeyExchange* m_DHExchange;
	Algorithm* m_Algorithm;
	Algorithm* m_PendingAlgorithm;

	uint32_t m_C2S_SequenceNumber;
	uint32_t m_S2C_SequenceNumber;

	size_t m_BufferDecryptedPosition;
};

} // namespace RSSH

#endif /* RSSH_TRANSPORT_H */
