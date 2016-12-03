#include "trace.h"
#include <stdarg.h>
#include <stdio.h>

namespace RSSH {
namespace Trace {

namespace {

unsigned int s_TraceMask = 0;

#define REPORT(CATEGORY, TYPE) \
	if (s_TraceMask & (1 << static_cast<unsigned int>(CATEGORY))) { \
		va_list va; \
		va_start(va, fmt); \
		fprintf(stderr, "%s: ", TYPE); \
		vfprintf(stderr, fmt, va); \
		fprintf(stderr, "\n"); \
		va_end(va); \
	}

} // unnamed namespace

void Info(const char* fmt, ...) {
	REPORT(C_Info, "Info")
}

void Error(const char* fmt, ...) {
	REPORT(C_Error, "Error")
}

void Warning(const char* fmt, ...) {
	REPORT(C_Warning, "Warning")
}

void Debug(const char* fmt, ...) {
	REPORT(C_Debug, "Debug")
}

void Enable(Category category) {
	s_TraceMask |= 1 << static_cast<unsigned int>(category);
}

void Disable(Category category) {
	s_TraceMask &= ~(1 << static_cast<unsigned int>(category));
}

void EnableAll() {
	s_TraceMask = static_cast<unsigned int>(-1);
}

void DisableAll() {
	s_TraceMask = 0;
}

} // namespace Trace
} // namespace RSSH
