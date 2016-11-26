#ifndef RSSH_TYPES_H
#define RSSH_TYPES_H

#include <string>
#include <vector>

namespace RSSH {

class Buffer;

namespace Types {

class NameList {
public:
	NameList() {
	}
	NameList(const std::string& s);

	std::string ToString() const;

	const std::vector<std::string>& GetNames() {
		return m_Names;
	}

private:
	std::vector<std::string> m_Names;
};

Buffer& operator>>(Buffer& buffer, NameList& nl);
Buffer& operator<<(Buffer& buffer, const NameList& nl);

} // namespace Types
} // namespace RSSH

#endif /* RSSH_TYPES_H */
