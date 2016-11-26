#include "trace.h"
#include <stdio.h>

namespace RSSH {
namespace Trace {

namespace {

#define REPORT(TYPE) \
	va_list va; \
	va_start(va, fmt); \
	fprintf(stderr, "%s: ", TYPE); \
	vfprintf(stderr, fmt, va); \
	fprintf(stderr, "\n"); \
	va_end(va)

} // unnamed namespace

void Info(const char* fmt, ...) {
	REPORT("Info");
}

void Error(const char* fmt, ...) {
	REPORT("Error");
}

void Warning(const char* fmt, ...) {
	REPORT("Warning");
}

void Debug(const char* fmt, ...) {
	REPORT("Debug");
}

} // namespace Trace
} // namespace RSSH
