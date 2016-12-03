#ifndef RSSH_SOCKET_H
#define RSSH_SOCKET_H

#include <cstddef>

namespace RSSH {

class Buffer;

//! Implements a socket-abstraction, using TCP
class Socket final {
public:
	Socket();
	~Socket();

	/*! Connects to a remote host
	 */
	bool Connect(const char* hostname, int port);

	/*! Receives the SSH greeting
	 *
	 *  May not truely belong here, yet the greeter has nothing in common
	 *  with the rest of the protocol...
	 */
	bool ReceiveGreeter(char* greeter, size_t max_length);

	//! Transmit our greeter
	bool TransmitGreeter(const char* greeter);

	//! Attempt to fill the buffer
	bool Fill(Buffer& buffer);

	//! Send the buffer
	bool Transmit(Buffer& buffer);

	/*! \brief Retrieve the socket's file descriptor
	 *
	 *  This is intended for use in things like select(2).
	 */
	int GetFD() const { return m_FD; }

private:
	//! File descriptor
	int m_FD;
};

} // namespace RSSH

#endif /* RSSH_SOCKET_H */
