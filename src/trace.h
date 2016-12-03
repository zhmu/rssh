#ifndef RSSH_TRACE_H
#define RSSH_TRACE_H

#include <cstddef>

namespace RSSH {
namespace Trace {

enum Category {
	C_Info,
	C_Error,
	C_Warning,
	C_Debug
};

void Info(const char* fmt, ...);
void Error(const char* fmt, ...);
void Warning(const char* fmt, ...);
void Debug(const char* fmt, ...);

void Enable(Category category);
void Disable(Category category);

void EnableAll();
void DisableAll();

} // namespace Trace
} // namespace RSSH

#endif /* RSSH_TRACE_H */
