#include "transport.h"
#include "algorithm.h"
#include "callback.h"
#include "dh-keyexchange.h"
#include "exception.h"
#include "numbers.h"
#include "random.h"
#include "trace.h"
#include "types.h"
#include <string.h>

namespace RSSH {

Transport::Transport(Callback& callback)
	: m_ServerKexPayload(NULL), m_MyKexPayload(NULL), m_DHExchange(NULL), m_Algorithm(NULL), m_PendingAlgorithm(NULL),
	  m_C2S_SequenceNumber(0), m_S2C_SequenceNumber(0), m_BufferDecryptedPosition(0), m_Callback(callback)
{
}

Transport::~Transport()
{
	delete m_PendingAlgorithm;
	delete m_Algorithm;
	delete m_DHExchange;
	delete[] m_ServerKexPayload;
	delete[] m_MyKexPayload;
}

void Transport::Connect(const char* hostname, int port)
{
	if (!m_Socket.Connect(hostname, port))
		throw Exception(Exception::C_Socket_Error);

	if (!m_Socket.ReceiveGreeter(m_Greeter, sizeof(m_Greeter)))
		throw Exception(Exception::C_Socket_Error);

	// [SSH-TRANS, 4.2] details the greeter; it must end in CR LF
	// XXX Do note that not all OpenSSH servers seem to do this?
	//     We are a bit more lenient
	{
		int s = strlen(m_Greeter);
		if (s < 2 || m_Greeter[s - 1] != '\n') {
			Trace::Error("got corrupt greeter [%s]", m_Greeter);
			throw Exception(Exception::C_Transport_Greeter_Corrupt);
		}
		if (m_Greeter[s - 2] == '\r')
			m_Greeter[s - 2] = '\0'; // cut off CR LF
		else
			m_Greeter[s - 1] = '\0'; // cut off LF
	}
	// It has to start with SSH-
	if (strncmp("SSH-", m_Greeter, 4) != 0) {
		Trace::Error("greeter [%s] does not start with SSH-", m_Greeter);
		throw Exception(Exception::C_Transport_Greeter_Corrupt);
	}
	// And the protocol version must be 2.0 (XXX should we accept 1.99 as well?)
	if (strncmp("2.0-", m_Greeter + 4, 4) != 0) {
		Trace::Error("invalid version, got %s, expected 2.0-", m_Greeter + 4);
		throw Exception(Exception::C_Transport_Version_Mismatch);
	}

	// XXX We should be able to process more messages here
	Trace::Info("got greeter [%s]", m_Greeter);
	m_Callback.OnGreeter(m_Greeter);

	// Now send our own greeter
	if (!m_Socket.TransmitGreeter(Numbers::ourGreeter))
		throw Exception(Exception::C_Socket_Error);

	// We should have moved to the binary protocol now, as outlined in [SSH-TRANS, 6]
}

void Transport::TransmitPacket(Buffer& buffer)
{
	int block_size = 8;
	if (m_Algorithm != NULL)
		block_size = m_Algorithm->GetBlockSize_C2S();

	// Determine packet length and padding to use
	uint32_t len = buffer.GetWritePosition();
	uint8_t padding_len = block_size - (len % block_size);
	// [SSH-TRANS] 5.3: there MUST be at least 4 bytes of padding
	if (padding_len < 4)
		padding_len += block_size;
	// Update header: length and padding length
	buffer.SetWritePosition(0);
	buffer << static_cast<uint32_t>(len + padding_len - sizeof(uint32_t) /* length field */);
	buffer << padding_len;

	// Write random padding bytes
	buffer.SetWritePosition(len);
	Random::GetInstance().Generate(buffer.GetWritePointer(), padding_len);
	buffer.SetWritePosition(buffer.GetWritePosition() + padding_len);

	// Perform HMAC/encryption
	if (m_Algorithm != NULL) {
		// Add the HMAC before encrypting
		m_Algorithm->PerformHMAC_C2S(buffer, m_C2S_SequenceNumber);

		// Now encrypt everything up to the HMAC
		m_Algorithm->Encrypt_C2S((uint8_t*)buffer.GetReadPointer(), buffer.GetAvailableBytes() - m_Algorithm->GetHMACSize_C2S());
	}
	m_C2S_SequenceNumber++;

	m_Socket.Transmit(buffer);
}

void Transport::SendKexInitReply()
{
	// Construct our KEXINIT reply - XXX we should look at what the server
	// supports rather than just hardcode our own idea...
	Buffer b;
	b << static_cast<uint32_t>(0); // len
	b << static_cast<uint8_t>(0); // padding len
	b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_KEXINIT);
	// Generate 16-byte random cookie
	Random::GetInstance().Generate(b.GetWritePointer(), 16);
	b.SetWritePosition(b.GetWritePosition() + 16);
	b << Types::NameList("diffie-hellman-group14-sha1"); // kex algos
	b << Types::NameList("ssh-rsa"); // hostkey
	b << Types::NameList("aes128-cbc"); // encr-c2s
	b << Types::NameList("aes128-cbc"); // encr-s2c
	b << Types::NameList("hmac-sha1"); // mac-c2s
	b << Types::NameList("hmac-sha1"); // mac-s2c
	b << Types::NameList("none"); // compr-c2s
	b << Types::NameList("none"); // compr-s2c
	b << Types::NameList(); // lang-c2s
	b << Types::NameList(); // lang-s2c
	b << false; // first-kex-packt-follows
	b << static_cast<uint32_t>(0); // reserved

	// Store our KEXINIT payload, it is part of what the server will sign
	delete[] m_MyKexPayload;
	m_MyKexPayloadLength = b.GetAvailableBytes() - 5 /* skip len/padding len */;
	m_MyKexPayload = new char[m_MyKexPayloadLength];
	memcpy(m_MyKexPayload, b.GetReadPointer() + 5, m_MyKexPayloadLength);

	// And off it goes
	TransmitPacket(b);
}

void Transport::OnMessageKexInit(Buffer& buffer, size_t packetLength, size_t paddingLength)
{
	// Make a copy of the payload; we need this to verify the signature later
	delete[] m_ServerKexPayload;
	m_ServerKexPayloadLength = packetLength - paddingLength - 1 /* skip padding byte */;
	m_ServerKexPayload = new char[m_ServerKexPayloadLength];
	memcpy(m_ServerKexPayload, m_Buffer.GetReadPointer() - 1 /* take command byte too */, m_ServerKexPayloadLength);

	// Skip the cookie; there is no need to read it as it is part of m_ServerKexPayload
	m_Buffer.SkipBytes(16);

	// Grab the packet contents
	Types::NameList kex_algos, hostkey_algos, encr_c2s, encr_s2c, mac_c2s, mac_s2c, compr_c2s, compr_s2c, lang_c2s, lang_s2c;
	bool follows;
	uint32_t reserved;
	buffer >> kex_algos >> hostkey_algos >> encr_c2s >> encr_s2c >> mac_c2s >> mac_s2c >> compr_c2s >> compr_s2c >> lang_c2s >> lang_s2c >> follows >> reserved;
	Trace::Debug("kex_algos = %s", kex_algos.ToString().c_str());
	Trace::Debug("hostkey_algos = %s", hostkey_algos.ToString().c_str());
	Trace::Debug("encr_c2s = %s", encr_c2s.ToString().c_str());
	Trace::Debug("encr_s2c = %s", encr_s2c.ToString().c_str());
	Trace::Debug("mac_c2s = %s", mac_c2s.ToString().c_str());
	Trace::Debug("mac_s2c = %s", mac_s2c.ToString().c_str());
	Trace::Debug("compr_c2s = %s", compr_c2s.ToString().c_str());
	Trace::Debug("compr_s2c = %s", compr_s2c.ToString().c_str());
	Trace::Debug("lang_c2s = %s", lang_c2s.ToString().c_str());
	Trace::Debug("lang_s2c = %s", lang_s2c.ToString().c_str());
	Trace::Debug("follows = %d", !!follows);
	Trace::Debug("reserved = %d", reserved);

	// TODO We should negotiate our options
	SendKexInitReply();

	// Initiate a DH key exchange
	delete m_DHExchange;
	m_DHExchange = new DHKeyExchange(*this, "diffie-hellman-group14-sha1"); // XXX
	m_DHExchange->SendExchange();
}

void Transport::SendDisconnect()
{
	Buffer b;
	b << static_cast<uint32_t>(0); // len
	b << static_cast<uint8_t>(0); // padding len
	b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_DISCONNECT);
	b << static_cast<uint32_t>(Numbers::DisconnectReason::SSH_DISCONNECT_BY_APPLICATION);
	b << std::string("goodbye world");
	b << std::string();
	TransmitPacket(b);
}

void Transport::RequestService(const char* serviceName)
{
	Buffer b;
	b << static_cast<uint32_t>(0); // len
	b << static_cast<uint8_t>(0); // padding len
	b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_SERVICE_REQUEST);
	b << std::string(serviceName);
	TransmitPacket(b);
}

void Transport::Process()
{
	if (!m_Socket.Fill(m_Buffer))
		throw Exception(Exception::C_Socket_Error);

	while(m_Buffer.GetAvailableBytes() >= sizeof(uint32_t)) {
		if (m_Algorithm != NULL && m_BufferDecryptedPosition < sizeof(uint32_t)) {
			// We first need to decrypt the length - note that we can't blindly jam all
			// bytes in the decryption code because the HMAC is not encrypted
			if (m_Buffer.GetAvailableBytes() < m_Algorithm->GetBlockSize_S2C()) {
				Trace::Debug("not enough bytes to decrypt (have %d, need %d)", m_Buffer.GetAvailableBytes(), m_Algorithm->GetBlockSize_S2C());
				return;
			}

			// We can decrypt the first block now
			m_Algorithm->Decrypt_S2C((uint8_t*)m_Buffer.GetReadPointer(), m_Algorithm->GetBlockSize_S2C());
			m_BufferDecryptedPosition += m_Algorithm->GetBlockSize_S2C();

		}

		// Process the data - front of the buffer is no longer encrypted
		uint32_t len;
		m_Buffer >> len;
		if (len < 1 || len > m_Buffer.GetSize()) {
			Trace::Error("got excessive length %d!", len);
			throw Exception(Exception::C_Transport_Invalid_Length);
		}
		if (len > m_Buffer.GetAvailableBytes()) {
			// Don't have the entire buffer
			m_Buffer.SetReadPosition(m_Buffer.GetReadPosition() - sizeof(uint32_t));
			break;
		}

		// Okay, we have an entire packet - handle decryption
		if (m_Algorithm != NULL) {
			if (len + m_Algorithm->GetHMACSize_S2C() > m_Buffer.GetAvailableBytes()) {
				Trace::Debug("packet not complete, missing HMAC (got %d, expected %d)", m_Buffer.GetAvailableBytes(), (int)(len + m_Algorithm->GetHMACSize_S2C()));
				m_Buffer.SetReadPosition(m_Buffer.GetReadPosition() - sizeof(uint32_t));
				break;
			}

			// [SSH-TRANS, 6] 'The length of 'packet_length',
			// 'padding_length', 'payload' and 'random_padding'
			// must be a multiple of the cipher size
			if ((len + 4) % m_Algorithm->GetBlockSize_S2C())
				throw Exception(Exception::C_Transport_Invalid_Length);

			// Decrypt the payload; the length doesn't include the
			// size (which we already decrypted), so skip that and
			// decrypt the packet contents - not the HMAC
			size_t left = (len + 4) - m_BufferDecryptedPosition;
			uint8_t* pos = (uint8_t*)m_Buffer.GetReadPointer() + m_BufferDecryptedPosition - 4;
			m_Algorithm->Decrypt_S2C(pos, left);
			m_BufferDecryptedPosition += left;

			// Now that we have decrypted everything, ensure the HMAC matches
			if (!m_Algorithm->CheckHMAC_S2C(m_Buffer.GetReadPointer() - 4, len + 4, m_S2C_SequenceNumber))
				throw Exception(Exception::C_HMAC_Mismatch);
		}
		m_BufferDecryptedPosition = 0;

		// We have an entire packet, and it has been verified. Now process it
		bool switch_algorithm = false;
		uint8_t padding_length, msg_type;
		m_Buffer >> padding_length >> msg_type;
		switch(static_cast<Numbers::MessageID>(msg_type)) {
			case Numbers::MessageID::SSH_MSG_KEXINIT: {
				Trace::Debug("got SSH_MSG_KEXINIT");
				OnMessageKexInit(m_Buffer, len, padding_length);
				break;
			}
			case Numbers::MessageID::SSH_MSG_KEXDH_REPLY: {
				Trace::Debug("got SSH_MSG_KEXDH_REPLY");
				if (m_DHExchange != NULL) {
					m_DHExchange->OnReply(m_Buffer);
					if (m_DHExchange->GetKeys() != NULL) {
						// XXX store chosen algorithm names
						m_PendingAlgorithm = new Algorithm("aes128-cbc", "aes128-cbc", "hmac-sha1", "hmac-sha1", *m_DHExchange->GetKeys());
					} else {
						Trace::Error("got SSH_MSG_KEXDH_REPLY but no keys?");
					}	
					delete m_DHExchange;
					m_DHExchange = NULL;
				} else {
					Trace::Warning("got unexpected SSH_MSG_KEXDH_REPLY, ignoring");
				}
				break;
			}
			case Numbers::MessageID::SSH_MSG_SERVICE_ACCEPT: {
				Trace::Debug("got SSH_MSG_SERVICE_ACCEPT");
				std::string channel_name;
				m_Buffer >> channel_name;

				Trace::Info("channel accept [%s]", channel_name.c_str());
				if (channel_name == "ssh-userauth") {
					Buffer b;
					b << static_cast<uint32_t>(0); // len
					b << static_cast<uint8_t>(0); // padding len
					b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_USERAUTH_REQUEST);
					b << std::string(m_Callback.GetUserName());
					b << std::string("ssh-connection");
					b << std::string(Numbers::AuthenticationMethodNames::KeyboardInteractive);
					b << std::string(); // language tag
					b << std::string(); // submethods
					TransmitPacket(b);
				}
				break;
			}
			case Numbers::MessageID::SSH_MSG_NEWKEYS: {
				Trace::Debug("got SSH_MSG_NEWKEYS");
				if (m_PendingAlgorithm != NULL) {
					// Acknowledge the request by sending a NEWKEYS
					{
						Buffer b;
						b << static_cast<uint32_t>(0); // len
						b << static_cast<uint8_t>(0); // padding len
						b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_NEWKEYS);
						TransmitPacket(b);
					}

					// Postpone switching algorithm until we clear the packet
					switch_algorithm = true;

				} else {
					Trace::Warning("got SSH_MSG_NEWKEYS without pending keys, ignoring");
				}
				break;
			}
			case Numbers::MessageID::SSH_MSG_USERAUTH_SUCCESS: {
				Trace::Debug("got SSH_MSG_USERAUTH_SUCCESS");

				// Want session
				{
					Buffer b;
					b << static_cast<uint32_t>(0); // len
					b << static_cast<uint8_t>(0); // padding len
					b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_CHANNEL_OPEN);
					b << std::string(Numbers::ConnectionProtocolAssignedNames::ChannelTypes::Session);
					b << static_cast<uint32_t>(0);
					b << static_cast<uint32_t>(4096); // window size
					b << static_cast<uint32_t>(1024); // max packet size

					TransmitPacket(b);
				}
				break;
			}
			case Numbers::MessageID::SSH_MSG_USERAUTH_INFO_REQUEST: {
				Trace::Debug("got SSH_MSG_USERAUTH_INFO_REQUEST");
				// [KBD-INT, 3.2]
				std::string name, instruction, language;
				uint32_t num_prompts;
				m_Buffer >> name >> instruction >> language >> num_prompts;
				Trace::Info("name '%s' instruction '%s' language '%s'", name.c_str(), instruction.c_str(), language.c_str());

				std::vector<AuthenticationPrompt> prompts;
				prompts.resize(num_prompts);
				for (unsigned int n = 0; n < num_prompts; n++)
					m_Buffer >> prompts[n].m_Prompt;
				for (unsigned int n = 0; n < num_prompts; n++)
					m_Buffer >> prompts[n].m_Echo;

				// If we got at least a single prompt, hand it to the application
				if (num_prompts > 0 && !m_Callback.OnAuthenticationPrompt(prompts))
					break; // application didn't want to reply 

				// Issue the reply [KBD-INT, 3.4]
				Buffer b;
				b << static_cast<uint32_t>(0); // len
				b << static_cast<uint8_t>(0); // padding len
				b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_USERAUTH_INFO_RESPONSE);
				b << static_cast<uint32_t>(num_prompts);
				for (unsigned int n = 0; n < num_prompts; n++)
					b << prompts[n].m_Reply;
				TransmitPacket(b);
				break;
			}
			case Numbers::MessageID::SSH_MSG_USERAUTH_FAILURE: {
				Trace::Debug("got SSH_MSG_USERAUTH_FAILURE");
				Types::NameList auths;
				bool partial;
				m_Buffer >> auths >> partial;

				Trace::Info("authentication failed, partial success = %s, next %s", partial ? "yes" : "no", auths.ToString().c_str());
				break;
			}
			case Numbers::MessageID::SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
				Trace::Debug("got SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
				uint32_t channelNumber, senderChannel, initialWindowSize, maxPacketSize;
				m_Buffer >> channelNumber >> senderChannel >> initialWindowSize >> maxPacketSize;
				Trace::Debug("channel %d sender %d iws %d mps %d", channelNumber, senderChannel, initialWindowSize, maxPacketSize);

				if (channelNumber == 0) {
					// want pty
					Buffer b;
					b << static_cast<uint32_t>(0); // len
					b << static_cast<uint8_t>(0); // padding len
					b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_CHANNEL_REQUEST);
					b << static_cast<uint32_t>(0);
					b << std::string(Numbers::ConnectionProtocolAssignedNames::RequestType::PtyReq);
					b << true; // want reply
					b << std::string("xterm");
					b << static_cast<uint32_t>(0);
					b << static_cast<uint32_t>(0);
					b << static_cast<uint32_t>(0);
					b << static_cast<uint32_t>(0);
					b << std::string();

					TransmitPacket(b);
				}
				break;
			}
			case Numbers::MessageID::SSH_MSG_CHANNEL_SUCCESS: {
				Trace::Debug("got SSH_MSG_CHANNEL_SUCCESS");
				uint32_t channelNumber;
				m_Buffer >> channelNumber;
				Trace::Debug("channel %d", channelNumber);

				// want shell
				Buffer b;
				b << static_cast<uint32_t>(0); // len
				b << static_cast<uint8_t>(0); // padding len
				b << static_cast<uint8_t>(Numbers::MessageID::SSH_MSG_CHANNEL_REQUEST);
				b << static_cast<uint32_t>(0);
				b << std::string(Numbers::ConnectionProtocolAssignedNames::RequestType::Shell);
				b << true; // want reply
				TransmitPacket(b);
				break;
			}
			case Numbers::MessageID::SSH_MSG_CHANNEL_DATA: {
				Trace::Debug("got SSH_MSG_CHANNEL_DATA");

				uint32_t channelNumber;
				std::string data;
				m_Buffer >> channelNumber >> data;
				Trace::Info("channel %d data [%s]", channelNumber, data.c_str());
				break;
			}
#if 0
			case Numbers::MessageID::SSH_MSG_GLOBAL_REQUEST: {
				Trace::Debug("got SSH_MSG_GLOBAL_REQUEST");
				std::string channel;
				bool want_reply;
				m_Buffer >> channel >> want_reply;
				printf("channel [%s] want_reply %s\n", channel.c_str(), want_reply ? "yes" : "no");
				break;
			}
#endif
			default: {
				Trace::Debug("unsupported message type %d ignored", msg_type);
				/* We just need to skip the payload of the message, not the padding/hash and msgtype/padding_len bytes */
				m_Buffer.SetReadPosition(m_Buffer.GetReadPosition() + len - padding_length - 2);
			}
		}

		// Skip random padding
		m_Buffer.SetReadPosition(m_Buffer.GetReadPosition() + padding_length);
		if (m_Algorithm != NULL) {
			// Skip HMAC; it's already validated by now
			m_Buffer.SetReadPosition(m_Buffer.GetReadPosition() + m_Algorithm->GetHMACSize_S2C());
		}
		m_Buffer.Shift();
		m_S2C_SequenceNumber++;

		// Perform sw
		if (switch_algorithm) {
			bool initial_algorithm_switch = m_Algorithm == NULL;
			delete m_Algorithm;
			m_Algorithm = m_PendingAlgorithm;
			m_PendingAlgorithm = NULL;

			// The initial switch to an algorithm means we have established the
			// transport connection
			if (initial_algorithm_switch)
				m_Callback.OnTransportEstablished();
		}
	}
}

} // namespace RSSH
