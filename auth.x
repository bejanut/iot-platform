
struct Auth_Response{
	int status;
	string accessToken<>;
	string refreshToken<>;
	int expiry;
};

struct Auth_Request{
	string requestToken<>;
	int shouldRefresh;
};

struct Action_Request{
	string accessToken<>;
	string resource<>;
	string action<>;
};

program LOAD_PROG {
	version LOAD_VERS {
		string request_Authorization(string) = 1;
		string approve_Request_Token(string) = 2;
		Auth_Response request_Access_Token(Auth_Request) = 3;
		Auth_Response refresh_Access_Token(string<>) = 4;
		int validate_Delegated_Action(Action_Request) = 5;
		void stop_Server(void) = 6;
	} = 1;
} = 123456789;
