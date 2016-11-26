#ifndef RSSH_CALLBACK_H
#define RSSH_CALLBACK_H

#include <string>
#include <vector>

namespace RSSH {

struct AuthenticationPrompt {
	std::string m_Prompt;
	bool m_Echo;
	std::string m_Reply;
};

class Callback {
public:
	//! Called when the SSH-2.0-... greeter from the host has been received
	virtual void OnGreeter(const std::string& greeter) { }

	//! Called when the transport is established - this means keys have been exchanged and services can be requested
	virtual void OnTransportEstablished() { }

	//! Returns the username to use
	virtual std::string GetUserName() = 0;

	//! Called to verify the host key signature, Base64-encoded. Return true to accept
	virtual bool OnVerifyHostKeySignature(const std::string& signature) { return false; }

	//! Authentication prompts; on return, provide the replies in 'm_Reply' and return true
	virtual bool OnAuthenticationPrompt(std::vector<RSSH::AuthenticationPrompt>& prompts) { return false; }
};

} // namespace RSSH

#endif /* RSSH_CALLBACK_H */
