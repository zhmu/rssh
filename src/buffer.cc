#include "buffer.h"
#include "exception.h"

#include <string.h>

#include "cryptopp/integer.h"

namespace RSSH {

namespace {

// [SSH-TRANS, 6.1]: 'All implementations MUST be able to process packets [...]  and a total packet size of 35000 bytes or less'
const size_t bufferSize = 35000;

} // unnamed namespace

Buffer::Buffer() {
	m_Size = bufferSize;
	m_Data = new uint8_t[m_Size];
	m_ReadPosition = 0;
	m_WritePosition = 0;
}

Buffer::Buffer(const uint8_t* buffer, size_t len) {
	m_Size = len;
	m_Data = new uint8_t[len];
	memcpy(&m_Data[0], &buffer[0], len);
	m_ReadPosition = 0;
	m_WritePosition = len;
}

Buffer::~Buffer() {
	delete[] m_Data;
}

Buffer::Position Buffer::GetAvailableBytes() const
{
	return m_WritePosition - m_ReadPosition;
}

void Buffer::SetReadPosition(Position p)
{
	if (p >= m_Size)
		throw Exception(Exception::C_Buffer_Too_Short);
	m_ReadPosition = p;
}

void Buffer::SetWritePosition(Position p)
{
	if (p >= m_Size)
		throw Exception(Exception::C_Buffer_Too_Short);
	m_WritePosition = p;
}

void Buffer::GetBytes(uint8_t* bytes, size_t len)
{
	if (len > GetAvailableBytes())
		throw Exception(Exception::C_Buffer_Out_Of_Data);
	memcpy(bytes, GetReadPointer(), len);
	SkipBytes(len);
}

void Buffer::SkipBytes(size_t len)
{
	m_ReadPosition += len;
}

void Buffer::Shift()
{
	size_t left = m_WritePosition - m_ReadPosition;
	memmove(&m_Data[0], &m_Data[m_ReadPosition], left);
	m_WritePosition = left;
	m_ReadPosition = 0;
}

Buffer& Buffer::operator>>(uint8_t& v)
{
	GetBytes(&v, sizeof(v));
	return *this;
}

Buffer& Buffer::operator>>(bool& v)
{
	uint8_t b;
	*this >> b;
	v = (b != 0);
	return *this;
}

Buffer& Buffer::operator>>(uint32_t& v)
{
	uint8_t b[4];
	GetBytes(b, sizeof(b));
	v = (uint32_t)b[0] << 24  | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | (uint32_t)b[3];
	return *this;
}

Buffer& Buffer::operator>>(std::string& v)
{
	uint32_t len;
	*this >> len;
	v = std::string((const char*)GetReadPointer(), len);
	m_ReadPosition += len;
	return *this;
}

void Buffer::PutBytes(const uint8_t* bytes, size_t len)
{
	if (m_WritePosition + len >= m_Size)
		throw Exception(Exception::C_Buffer_Full);
	memcpy(GetWritePointer(), bytes, len);
	m_WritePosition += len;
}

void Buffer::PutData(const uint8_t* bytes, size_t len)
{
	*this << static_cast<uint32_t>(len);
	PutBytes(bytes, len);
}

Buffer& Buffer::operator<<(uint8_t v)
{
	PutBytes(&v, sizeof(v));
	return *this;
}

Buffer& Buffer::operator<<(bool v)
{
	uint8_t b = v ? 1 : 0;
	*this << b;
	return *this;
}

Buffer& Buffer::operator<<(uint32_t v)
{
	uint8_t bytes[4] = {
		static_cast<uint8_t>((v >> 24) & 0xff),
		static_cast<uint8_t>((v >> 16) & 0xff),
		static_cast<uint8_t>((v >> 8) & 0xff),
		static_cast<uint8_t>(v & 0xff)
	};
	PutBytes(bytes, sizeof(bytes));
	return *this;
}

Buffer& Buffer::operator<<(const std::string& v)
{
	size_t len = v.size();
	*this << static_cast<uint32_t>(len);
	PutBytes((const uint8_t*)v.c_str(), len);
	return *this;
}

Buffer& Buffer::operator>>(CryptoPP::Integer& v)
{
	uint32_t len;
	*this >> len;
	if (len > GetAvailableBytes())
		throw Exception(Exception::C_Buffer_Out_Of_Data);
	v.Decode(GetReadPointer(), len);
	m_ReadPosition = (m_ReadPosition + len) % m_Size;
	return *this;
}

Buffer& Buffer::operator<<(const CryptoPP::Integer& v)
{
	size_t len = v.MinEncodedSize(CryptoPP::Integer::SIGNED);
	if (m_WritePosition + len >= m_Size)
		throw Exception(Exception::C_Buffer_Full);
	*this << static_cast<uint32_t>(len);
	v.Encode(GetWritePointer(), len, CryptoPP::Integer::SIGNED);
	m_WritePosition = (m_WritePosition + len) % m_Size;
	return *this;
}

} // namespace RSSH
