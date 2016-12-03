#ifndef RSSH_CALLBACK_H
#define RSSH_CALLBACK_H

#include <string>
#include <vector>

namespace RSSH {

namespace Types {
class NameList;
}

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

	//! Called when authentication succeeds
	virtual void OnAuthenticationSuccess() { }

	//! Called when authentication fails
	virtual void OnAuthenticationFailure(bool partial_success, const Types::NameList& next_auths) { }

	//! Called once a channel is successfully opened
	virtual void OnChannelOpened(int channelNumber) { }

	//! Called once the server accepts a given service
	virtual void OnServiceAccepted(const std::string& serviceName) { }

	//! Called once a channel request succeeded
	virtual void OnChannelRequestSuccess(int channelNumber) { }

	//! Called once a channel request failed
	virtual void OnChannelRequestFailure(int channelNumber) { }

	//! Called once channel data arrives
	virtual void OnChannelData(int channelNumber, const std::string& data) { }
};

} // namespace RSSH

#endif /* RSSH_CALLBACK_H */
