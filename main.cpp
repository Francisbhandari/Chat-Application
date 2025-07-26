#include <iostream>
#include <string>
#include <fstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <cstring>


class Message{
	std::string usr;
	std::string msg;
	public:
		Message(std::string u, std::string m) :usr(u), msg(m) {}
	
		void Put_Message(std::string file){
			std::ofstream outfile(file, std::ios::app);
			if(!outfile){
				std::cerr << "Message writing error\n";
				std::exit(1);
			}

			outfile << usr << '\n' << msg << '\n';
			outfile.close();
		}

		std::string get_usr(){
			return usr;
		}

		std::string get_msg(){
			return msg;
		}

		std::string formatted_msg(){
			return usr + ": " + msg;
		}
};

class Crypt{
	std::string msg;
	int key;
	public:
		//for messages
		Crypt(std::string m, std::string password) :msg(m){
			const char *a = password.c_str();
			int k = 0;
			for(int i=0; a[i] != '\0'; i++){
				k += a[i];
			}
			key = k;
		}

		//for password
		Crypt(std::string p) :msg(p){
			const char *a = msg.c_str();
			int k = 0;
			for(int i=0; a[i] != '\0'; i++){
				k += a[i];
			}
			key = k;
		}

		void encryption(){
			std::string result = "";

			for(char ch : msg){
				if (ch>='A' && ch<='Z')
					result += 'A' + (ch-'A' + key)%26;

				else if (ch>='a' && ch<='z')
					result += 'a' + (ch-'a' + key)%26;
				else
					result += ch;
			}
			msg = result;
		}
		//for messages only
		void decryption(){
			std::string result = "";

			for(char ch : msg){
				if (ch>='A' && ch<='Z')
					result += 'A' + (ch-'A' - (key%26) +26)%26;

				else if (ch>='a' && ch<='z')
					result += 'a' + (ch-'a' - (key%26) +26)%26;
				else
					result += ch;
			}
			msg = result;
		}

		std::string get(){
			return msg;
		}
};

class ReadFile{
	std::ifstream infile;
	public:
		ReadFile(){}
		ReadFile(std::string filename) :infile(filename) {}

		std::vector<Message> Load_Messages(){
			if(!infile){
				std::cerr << "Message file reading error\nUnable to load messages\n";
			}

			std::vector<Message> msg_list;
			std::string usr, msg;

			while(std::getline(infile, usr) && std::getline(infile, msg)){
				msg_list.push_back({usr, msg});
			}

			infile.close();
			return msg_list;
		}
};

class User{
	std::string username;
	std::string password;
	std::string status;
	public:
		User(){}
		User(std::string usr, std::string pass, std::string s) :username(usr), password(pass), status(s){}
		
					
		void AddUser(){
			std::ofstream outfile("users.txt", std::ios::app);
			if(!outfile){
				std::cerr << "User file writing error\n";
				std::exit(1);
			}

			outfile << username << '\n' << password << '\n';
			outfile.close();
		}
		
		int VerifyUser(){
			std::ifstream infile("users.txt");
			if(!infile){
				std::cerr << "User file reading error\n";
				std::exit(1);
			}

			std::string usr, pswd;

			while(std::getline(infile, usr) && std::getline(infile, pswd)){

				if(username==usr && password==pswd){
					return 0;
				}
			}
			return 1;
		}

		std::string get_username(){
			return username;
		}

		std::string get_status(){
			return status;
		}

		std::string get_password(){
			return password;
		}
};

class Server{
	int fd, n_fd;
	char *port;
	struct addrinfo hints, *res, *p;
	struct sockaddr_in their_addr;
	socklen_t their_addr_size;
	std::string their_ipv4;
	User user;

	public:
		Server(char *a) :port(a){
			memset(&hints, 0, sizeof hints);
			hints.ai_family = AF_INET;
			hints.ai_flags = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			int s = getaddrinfo(NULL, port, &hints, &res);
			if (s != 0){
				std::cerr<<"getaddrinfo : "<<gai_strerror(s)<<std::endl;
				std::exit(1);
			}

			for (p=res; p != NULL; p=p->ai_next){
				fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
				if (fd == -1){
					std::cerr <<"socket\n";
					continue;
				}

				int yes = 1;
				if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1){
					std::cerr << "setsockopt\n";
					std::exit(1);
				}

				if (bind(fd, p->ai_addr, p->ai_addrlen) == -1){
					std::cerr << "bind\n";
					close(fd);
					continue;
				}
				break;
			}
			freeaddrinfo(res);

			if (p == NULL){
				std::cerr << "Failed to bind"<<std::endl;
				std::exit(1);
			}

			if (listen(fd, 5) == -1){
				std::cerr << "listen"<<std::endl;
				std::exit(1);
			}
		}

		~Server(){
			close(fd);
			close(n_fd);
		}

		void AcceptConnection(){
			their_addr_size = sizeof their_addr;
			n_fd = accept(fd, (struct sockaddr *)&their_addr, &their_addr_size);
			if (n_fd == -1){
				std::cerr << "accept"<<std::endl;
				std::exit(1);
			}

			char ipstr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(their_addr.sin_addr), ipstr, INET_ADDRSTRLEN);
			their_ipv4 = std::string(ipstr);
			std::cout << "Connection established with " << their_ipv4 << std::endl<<std::endl;
		}
		
		std::string SendReceive(std::string send_message, int mode=0){
			int s = send(n_fd, send_message.c_str(), send_message.size(), 0);
			if (s == -1){
				std::cerr<< "send error\n";
				std::exit(1);
			}
			if (mode != 0)
				return "";

			char buf[100];
			int r = recv(n_fd, buf, sizeof(buf)-1, 0);
			if (r == -1){
				std::cerr << "recv error" <<std::endl;
				std::exit(1);
			}
			buf[r-1] = '\0';
			std::string recv_message(buf);
			return recv_message;
		}

		void Login(){
			std::string uname = SendReceive("Enter username: ");
			std::string pass = SendReceive("Enter password: ");

			Crypt pswd(pass);
			pswd.encryption();
			user = User(uname, pswd.get(), "old");
			int check = user.VerifyUser();

			if (check != 0){
				SendReceive("Incorrect username or password\n", 1);
				std::cerr << "Login error\n";
				std::exit(1);
			}

			SendReceive("Login Successful\n", 1);
			std::cout << "Verification Complete\n";
		}
		
		void CreateUser(){
			std::string uname = SendReceive("Enter username: ");
			std::string pass = SendReceive("Enter password: ");
			
			Crypt pswd(pass);
			pswd.encryption();
			user = User(uname, pswd.get(), "new");
			int check = user.VerifyUser();

			if (check == 0){
				SendReceive("User already exists\n", 1);
				std::cerr << "Create User error\n";
				std::exit(1);
			}

			user.AddUser();
			std::cout << "User Added Successfully\n";
			SendReceive("Registered Successfully\n", 1);
		}

		void Conversation(){
			if (user.get_status() == "old"){
				std::cout << "Old messages\n";
				SendReceive("Old messages\n", 1);

				ReadFile filehandler(user.get_username() + ".txt");
				std::vector<Message> msg_list = filehandler.Load_Messages();
				for (Message msg : msg_list){
					Crypt decryptor1(msg.get_msg(), user.get_password());
					decryptor1.decryption();
					Crypt decryptor2(msg.get_usr(), user.get_password());
					decryptor2.decryption();

					Message m1(decryptor2.get(), decryptor1.get());
					SendReceive(m1.formatted_msg() + "\n", 1);
					std::cout << m1.formatted_msg() << std::endl;
				}
			}
			std::cout<<"\n\nEnter bye to exit the conversation";
			SendReceive("\n\nEnter bye to exit the conversation\n", 1);
			
			std::string send_msg, recv_msg;
			std::vector<Message> new_msg;

			while(true){
				std::cout << "\nServer: ";
				std::getline(std::cin, send_msg);

				Message talk("Server", send_msg);
				new_msg.push_back(talk);

				recv_msg = SendReceive(talk.formatted_msg()+"\n"+user.get_username()+": ");

				talk = Message(user.get_username(), recv_msg);
				std::cout << talk.formatted_msg();
				new_msg.push_back(talk);

				if (send_msg == "bye"){
					SendReceive("\nServer is disconnecting\n", 1);
					break;
				}

				if(recv_msg == "bye"){
					std::cout << "\n\nClient disconnected" << std::endl;
					break;
				}


			}
			
			for(Message m : new_msg){
				Crypt encryptor1(m.get_msg(), user.get_password());
				encryptor1.encryption();
				Crypt encryptor2(m.get_usr(), user.get_password());
				encryptor2.encryption();

				Message putter(encryptor2.get(), encryptor1.get());
				putter.Put_Message(user.get_username()+".txt");
			}

			std::cout << "\nConversation ended" << std::endl;
			SendReceive("\nConversation ended\n", 1);
		}
};


int main(int argc, char *argv[]){
	if (argc != 2){
		std::cerr << "Enter port only\n";
		return 1;
	}
	Server server(argv[1]);
	server.AcceptConnection();

	int a;
	std::string verf_msg = "New user or old user (new/old): ";
	std::string usr = server.SendReceive(verf_msg);
	if (usr == "old"){
		server.SendReceive("\nVerifying\n\n", 1);
		std::cout << "Verifying\n\n";
		server.Login();
	}
	else if(usr == "new"){
		server.SendReceive("\nCreating new\n\n", 1);
		std::cout << "Creating new\n\n";
		server.CreateUser();
	}
	else{
		std::cerr << "Unknown choice. Closing\n";
		return 2;
	}

	server.Conversation();
	return 0;
}
