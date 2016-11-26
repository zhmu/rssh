#include "socket.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"

namespace RSSH {

Socket::Socket()
	: m_FD(-1)
{
}

Socket::~Socket()
{
	if (m_FD >= 0)
		close(m_FD);
}

bool Socket::Connect(const char* hostname, int port)
{
	assert(m_FD < 0); // don't be already connected
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char service[64];
	snprintf(service, sizeof(service) - 1, "%d", port);
	service[sizeof(service) - 1] = '\0';

	struct addrinfo* result;
	if (getaddrinfo(hostname, service, &hints, &result) != 0)
		return false;

	// Try to connect to each result
	int fd = -1;
	for(struct addrinfo* ai = result; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break; // got a connection

		close(fd);
		fd = -1;
	}
	freeaddrinfo(result);
	if (fd < 0)
		return false; // nothing worked

	m_FD = fd;
	return true;
}

bool Socket::ReceiveGreeter(char* greeter, size_t max_length)
{
	assert(m_FD >= 0); // be connected

	int s = read(m_FD, greeter, max_length - 1 /* terminating \0 */);
	if (s <= 0)
		return false;

	greeter[s] = '\0';
	return true;
}

bool Socket::TransmitGreeter(const char* greeter)
{
	int n = strlen(greeter) + 2;
	char* s = new char[n + 1];
	strcpy(s, greeter);
	strcat(s, "\r\n"); 
	bool ok = write(m_FD, s, n) == n;
	delete[] s;
	return ok;
}

bool Socket::Fill(Buffer& buffer)
{
	int left = buffer.GetSize() - buffer.GetWritePosition();
	int n = read(m_FD, buffer.GetWritePointer(), left);
	if (n <= 0)
		return false;
	buffer.SetWritePosition(buffer.GetWritePosition() + n);
	return true;
}

bool Socket::Transmit(Buffer& buffer)
{
	int len = buffer.GetWritePosition();
	int n = write(m_FD, static_cast<const void*>(buffer.GetReadPointer()), len);
	return n == len;
}

} // namespace RSSH
