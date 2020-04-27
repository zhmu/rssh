#include <sys/types.h>
#include <err.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "callback.h"
#include "exception.h"
#include "numbers.h"
#include "trace.h"
#include "transport.h"
#include "types.h"

namespace {

bool AskForPassword(RSSH::AuthenticationPrompt& prompt)
{
	int fd = open("/dev/tty", O_RDWR);
	if (fd < 0)
		return false;

	struct termios tios;
	if (!prompt.m_Echo) {
		tcgetattr(fd, &tios);
		tios.c_lflag &= ~ECHO;
		tcsetattr(fd, TCSAFLUSH, &tios);
	}

	printf("%s", prompt.m_Prompt.c_str());
	fflush(stdout);
	char password[256]; // XXX some arbitrary limit
	int n = read(fd, password, sizeof(password) - 1);
	if (n >= 0) {
		// Cut off any \n
		while(n > 0 && password[n - 1] == '\n')
			n--;
		password[n] = '\0';
		prompt.m_Reply = password;
	}
	printf("\n");

	if (!prompt.m_Echo) {
		tcgetattr(fd, &tios);
		tios.c_lflag |= ECHO;
		tcsetattr(fd, TCSAFLUSH, &tios);
	}

	close(fd);
	return !prompt.m_Reply.empty();
}

bool ParseConnectionSpecifier(const char* arg, std::string& username, std::string& host, int& port)
{
	const char* ptr = strchr(arg, '@');
	if (ptr != NULL) {
		username = std::string(arg, ptr - arg);
		arg = ptr + 1;
	} else {
		// No username specified; use the current one
		struct passwd* pw = getpwuid(getuid());
		if (pw != NULL)
			username = std::string(pw->pw_name);
	}

	ptr = strchr(arg, ':');
	if (ptr != NULL) {
		host = std::string(arg, ptr - arg);
		port = atoi(ptr + 1);
	} else {
		host = arg;
		port = 22;
	}

	return !username.empty() && !host.empty() && port != 0;
}

} // unnamed namespace

int
main(int argc, char* argv[])
{
	class Callback : public RSSH::Callback {
	public:
		Callback() : m_Transport(NULL) { }
		void SetTransport(RSSH::Transport& transport) {
			m_Transport = &transport;
		}

		void OnGreeter(const std::string& greeter) override {
			printf("Got server greeter [%s]\n", greeter.c_str());
		}

		void OnTransportEstablished() override {
			m_Transport->RequestService(RSSH::Numbers::ServiceNames::UserAuth);
		}

		std::string GetUserName() override {
			return m_Username;
		}

		bool OnAuthenticationPrompt(std::vector<RSSH::AuthenticationPrompt>& prompts) override {
			bool result = true;	
			for(RSSH::AuthenticationPrompt& prompt: prompts) {
				result &= AskForPassword(prompt);
			}
			return result;
		}

		bool OnVerifyHostKeySignature(const std::string& signature) override {
			printf("Accepting server hostkey signature: %s\n", signature.c_str());
			return true;
		}

		void OnAuthenticationFailure(bool partial_success, const RSSH::Types::NameList& next_auths) override {
			printf("authentication failed, partial success = %s, next %s\n", partial_success ? "yes" : "no", next_auths.ToString().c_str());
		}

		void OnAuthenticationSuccess() override {
			m_Transport->OpenChannel(0, RSSH::Numbers::ConnectionProtocolAssignedNames::ChannelTypes::Session);
		}

		void OnChannelOpened(int channelNumber) override {
			if (channelNumber == 0)
				m_Transport->RequestPty(0, "xterm");
		}

		void OnServiceAccepted(const std::string& serviceName) override {
			if (serviceName == RSSH::Numbers::ServiceNames::UserAuth) {
				m_Transport->RequestUserAuth(RSSH::Numbers::ServiceNames::Connection, m_Username);
			}
		}

		void OnChannelRequestSuccess(int channelNumber) override {
			if (channelNumber == 0) /* PTY */ {
				m_Transport->RequestChannel(0, RSSH::Numbers::ConnectionProtocolAssignedNames::RequestType::Shell);
			}
		}

		void OnChannelRequestFailure(int channelNumber) override {
			fprintf(stderr, "unable to open channel %d\n", channelNumber);
		}

		void OnChannelData(int channelNumber, const std::string& data) override {
			write(STDOUT_FILENO, data.c_str(), data.length());
			m_Transport->AdjustChannelWindow(channelNumber, data.size()); // XXX should we immediately do this?
		}

		void SetUsername(const std::string& username) {
			m_Username = username;
		}

	private:
		RSSH::Transport* m_Transport;
		std::string m_Username;
	} callback;

	if (argc != 2 && argc != 3)
		errx(1, "usage: %s [-d] [user@]host[:port]", argv[0]);

    if (argc == 3) {
        if (std::string(argv[1]) != "-d")
		    errx(1, "usage: %s [-d] [user@]host[:port]", argv[0]);
        RSSH::Trace::EnableAll();
    }

	std::string username, host;
	int port;
    {
        int connect_arg = argc == 2 ? 1 : 2;
        if (!ParseConnectionSpecifier(argv[connect_arg], username, host, port))
            errx(1, "unable to parse connection specifier");
    }

	RSSH::Transport t(callback);
	callback.SetTransport(t);
	callback.SetUsername(username);
	try {
		t.Connect(host.c_str(), port);
		int socketFd = t.GetSocket().GetFD();
		for(;;) {
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(STDIN_FILENO, &fds);
			FD_SET(socketFd, &fds);

			int n = select(socketFd + 1, &fds, NULL, NULL, NULL);
			if (n < 0)
				break;
			if (FD_ISSET(socketFd, &fds))
				t.Process();
			if (FD_ISSET(STDIN_FILENO, &fds)) {
				char buf[1024];
				int n = read(STDIN_FILENO, buf, sizeof(buf));
				if (n > 0)
					t.TransmitChannelData(0, std::string(buf, n));
			}
		}
	} catch (RSSH::Exception& e) {
		fprintf(stderr, "exception: %s\n", e.what());
	}

	return 0;
}
