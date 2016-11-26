#ifndef RSSH_TRACE_H
#define RSSH_TRACE_H

#include <cstddef>

namespace RSSH {
namespace Trace {

void Info(const char* fmt, ...);
void Error(const char* fmt, ...);
void Warning(const char* fmt, ...);
void Debug(const char* fmt, ...);

} // namespace Trace
} // namespace RSSH

#endif /* RSSH_TRACE_H */
