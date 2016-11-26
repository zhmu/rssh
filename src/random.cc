#include "random.h"

namespace RSSH {

namespace {
Random s_Random;
} // unnamed namespace

Random& Random::GetInstance()
{
	return s_Random;
}

} // namespace RSSH
