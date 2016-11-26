#ifndef RSSH_BUFFER_H
#define RSSH_BUFFER_H

#include <cstddef>
#include <stdint.h>
#include <string>

namespace CryptoPP {
class Integer;
} // namespace CryptoPP

namespace RSSH {

/*! Implements a storage-buffer for use with connections
 *
 *  The idea is that this can keep received data, which can in turn be decoded
 *  piece-by-piece.
 */
class Buffer final
{
public:
	typedef size_t Position;

	Buffer();
	Buffer(const uint8_t* buffer, size_t len);
	~Buffer();

	Buffer(const Buffer&) = delete;
	Buffer& operator=(const Buffer&) = delete;

	//! Fetch the current read offset, in bytes
	Position GetReadPosition() const {
		return m_ReadPosition;
	}

	//! Fetch the current write offset, in bytes
	Position GetWritePosition() const {
		return m_WritePosition;
	}

	uint8_t* GetWritePointer() {
		return &m_Data[m_WritePosition];
	}
	const uint8_t* GetReadPointer() const {
		return &m_Data[m_ReadPosition];
	}

	//! Sets the current read offset
	void SetReadPosition(Position p);

	//! Sets the current write offset
	void SetWritePosition(Position p);

	//! How large is the buffer?
	Position GetSize() const {
		return m_Size;
	}

	//! How many bytes are left to read?
	Position GetAvailableBytes() const;

	void SkipBytes(size_t len);
	void GetBytes(uint8_t* bytes, size_t len);

	Buffer& operator>>(uint8_t& v);
	Buffer& operator>>(bool& v);
	Buffer& operator>>(uint32_t& v);
	Buffer& operator>>(std::string& v);
	Buffer& operator>>(CryptoPP::Integer& v);

	void PutBytes(const uint8_t* bytes, size_t len);
	void PutData(const uint8_t* buffer, size_t len);
	Buffer& operator<<(uint8_t v);
	Buffer& operator<<(bool v);
	Buffer& operator<<(uint32_t v);
	Buffer& operator<<(const std::string& v);
	Buffer& operator<<(const CryptoPP::Integer& v);

	void Shift();

private:
	//! Buffer
	uint8_t* m_Data;

	//! Position where the next data will be read from
	Position m_ReadPosition;

	//! Position where the next data will be stored
	Position m_WritePosition;

	//! Buffer size, in bytes
	Position m_Size;
};

} // namespace RSSH

#endif /* RSSH_BUFFER_H */
