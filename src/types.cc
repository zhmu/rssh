#include "types.h"
#include "buffer.h"

namespace RSSH {
namespace Types {

NameList::NameList(const std::string& s)
{
	for (int cur_pos = 0; cur_pos != std::string::npos; /* nothing */) {
		int next_pos = s.find(',', cur_pos);
		if (next_pos == std::string::npos) {
			m_Names.push_back(s.substr(cur_pos));
			break;
		}
		m_Names.push_back(s.substr(cur_pos, next_pos - cur_pos));
		cur_pos = next_pos + 1;
	}
}

std::string NameList::ToString() const
{
	std::string s;
	for(auto& name: m_Names) {
		if (!s.empty())
			s += ",";
		s += name;
	}
	return s;
}

Buffer& operator>>(Buffer& b, NameList& nl)
{
	std::string s;
	b >> s;
	nl = NameList(s);
	return b;
}

Buffer& operator<<(Buffer& b, const NameList& nl)
{
	b << nl.ToString();
	return b;
}

} // namespace Types
} // namespace RSSH
