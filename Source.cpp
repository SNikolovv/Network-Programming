#define _WIN32_WINNT 0x501
#include <iostream>
#include <string>
#include <cstring>
#include<vector>
#include <WinSock2.h>
#include <ws2tcpip.h>

using namespace std;

#pragma comment (lib, "ws2_32.lib")


string  SpamhausDNSBL(const char* ip)
{
	string strIp = ip;
	size_t found = strIp.find_last_of(".");
	int lastOctet = stoi(strIp.substr(found + 1));
	string result;
	

	switch (lastOctet %10)
	{
	case 2: result = "SBL - Spamhaus SBL Data"; break;
	case 3: result = "SBL - Spamhaus SBL CSS Data"; break;
	case 4:result = "XBL - CBL Data"; break;
	case 9:result = "SBL - Spamhaus DROP/EDROP Data"; break;
	case 0: result = "PBL - ISP Maintained"; break;
	case 1: result = "PBL - Spamhaus Maintained"; break;
	default:result = ""; break;
	}
	
	return result;
	
}
const char* IPconvert(const char* ip)  
{
	string result = "";
	vector<string> octets;
	string octet = ""; 
	for (int i = 0; ip[i]; ++i) 
	{
		if (ip[i] != '.') 
		{
			octet = octet+ ip[i];
		}
		else
		{
			octets.push_back(octet);
			octet = "";
		}
	}
	octets.push_back(octet);
	
	for (vector<string>::reverse_iterator i = octets.rbegin();i != octets.rend(); ++i)
	{
		result =result+ *i + '.';
	}
	result = result + "zen.spamhaus.org";
	return result.c_str();
}


int main(int argc, char* argv[])
{
	
	if (argc < 2)
	{
		cerr << "Invalid input!";
		return -1;
	}


	WORD wordVersion = MAKEWORD(2, 0);
	WSADATA wsadata;

	if (WSAStartup(wordVersion, &wsadata) != 0) 
	{
		return 1;
	}

	char host[NI_MAXHOST + 1];
	for (int i = 1; argv[i]; ++i)
	{
		const char* convertIP = IPconvert(argv[i]);

		addrinfo addr;
		addrinfo* result = nullptr;
		memset(&addr, 0, sizeof(addrinfo));

		addr.ai_family = AF_INET;
		addr.ai_socktype = SOCK_DGRAM;
		
		int info = getaddrinfo(convertIP, nullptr, &addr, &result);
		if (info) 
		{
			cerr << "The IP adress: " << argv[i] << " is NOT found in the Spamhaus blacklists." << endl;
		}
		else 
		{

			cout << "The IP address: " << argv[i] << " is found in the following Spamhaus public IP zone: ";
			for (addrinfo* r = result; r != nullptr; r = r->ai_next) 
			{
				int res = getnameinfo(r->ai_addr, r->ai_addrlen, host, NI_MAXHOST, nullptr, NI_MAXSERV, NI_NUMERICHOST);
				if (res != 0) 
				{
					cerr << "Function getnameinfo failed!";
				}
				else 
				{
					cout << host << " - " << SpamhausDNSBL(host) << endl;
				}
			}

			freeaddrinfo(result);
			}

	}
	
	return 0;
}