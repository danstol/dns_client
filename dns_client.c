#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<time.h>

#define MAXSIZE 256
#define MAXqueryname 63
#define MAX16 65536
#define DNSPORT 53
#define FLAG 0x0200

/***************************************************************************
 *	Purpose: To write a DNS client. Particularly create a query, and parse the response
 *
 *	Notes:	There is a bug somewhere (that eludes me to no end)that for some replies
 *			the rdata get shifted by a byte and essentially writes only the first
 *			three bytes. Those answers i marked with /24 (block 24. (FIXED, or so rare as to be irrelevent)
 ***************************************************************************/
 
/*struct dnsheader, 12 bytes*/
struct dnsheader
{
	//2 byte ID
	uint16_t id;

	//2 byte flag broken down with bitfields
	//BYTE 1 in REVERSE ORDER 	//pos
	unsigned char rd :1; 		//7
	unsigned char tc :1;		//6
	unsigned char aa :1; 		//5
	unsigned char opcode :4;	//4-1
	unsigned char qr :1; 		//0
	
	//BYTE 2 in REVERSE ORDER
	unsigned char rcode :4;		//15-12 
	unsigned char z :3; 		//12-9	
	unsigned char ra :1; 		//9-8
	
	//counts, each 2 bytes
	uint16_t q_count; 
	uint16_t ans_count; 
	uint16_t auth_count; 
	uint16_t add_count;
	
	//unsigned char *name; //maximum length of the name
	//struct query *queryname;
	//uint16_t qtype;
	//uint16_t qclass;
};

/* struct question, contains qtype and qclass*/
struct question
{
	uint16_t qtype;
	uint16_t qclass;
};

/* struct record*/
struct record
{
	uint16_t name;		//2 byte pointer
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
	unsigned char* rdata;
};
/* struct query, contains the actual name requested and the struct question with qtype and qclass*/
struct query
{
	unsigned char *name;
	struct question *ques;
};

/*	The idea is simple, AND the ip with 0xFF ==> 11111111, which corresponds to an ip byte, then shift 
	by 8 (1 byte) and do the same thing*/
void convert(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;     
	if(bytes[0] == 4)
		printf("%d.%d.%d.00/24 (block 24)\n", bytes[1], bytes[2], bytes[3]); 
    else
		printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);        
}

/*Given rcode, parses the reply and gives the appropiate response message*/
void status(int rcode){
	switch(rcode){
		case 0:
			printf("0 (no error)\n");
			break;
		case 1:
			printf("1 (format error)\n");
			printf("Number of addresses found:0\nEnd of Processing");
			exit(0);
			break;
		case 2:
			printf("2 (server failure)\n");
			printf("Number of addresses found:0\nEnd of Processing");
			exit(0);
			break;
		case 3:		
			printf("3 (name error)\n");	
			printf("Number of addresses found:0\nEnd of Processing");
			exit(0);
			break;
		case 4:
			printf("4 (not implemented)\n");
			printf("Number of addresses found:0\nEnd of Processing");
			exit(0);
			break;
		case 5:
			printf("5 (refused)\n");
			printf("Number of addresses found:0\nEnd of Processing");
			exit(0);
			break;
	}	
}

void print(unsigned char* array, char *message){
	int count;
	printf("%s \n", message);
	char *byte;
	for(byte = array; *byte != EOF; byte++){
		if(*byte != 0){
			printf("%x ", (uint8_t)*byte);
			count++;
			if(count %16 == 0)
				printf("\n");
		}
	}
}
int letter_counter = 0;
/* Purpose: formats the given hostname into a dns query format, as in 3www5yahoo3com */
void seperate(unsigned char* name,unsigned char* host)
{
	char *tokens = strtok(host, ".");
	int counter = 0;
	while(1){
		if(tokens == NULL){
			break;
		}else{
			char *i;
			name[letter_counter] = (unsigned char)strlen(tokens);
			letter_counter++;
			//printf("\nLength of Label 0x%x \n0x", strlen(tokens));
			for(i = tokens; *i != NULL; i++){
				//printf("%x", *i);
				name[letter_counter] = *i;
				letter_counter++;
			}
		}
		tokens = strtok(NULL, ".");
	}
	name[letter_counter] = '\0';
	//printf("\nqueryname is: %s %x \t sum is:%d\n\n", name, name, letter_counter+1);
}

int main(int argc, char *argv[])
{
	if(argc != 3){
		printf("Not Enough Parameters\n USAGE: ./a2 <domain> <dns_ip_address>");
		exit(0);
	}
	
	char *hostname = argv[1];
	printf("hostname:%s\n", hostname);
	char *dnsserverip = argv[2];
	printf("DNS server:%s\n", dnsserverip);
	
	unsigned char buf[256];			//used to create the query
	unsigned char* queryname;
	
	struct record *answer;			//used to parse the ANSWERS
	struct question *queryinfo;
    struct sockaddr_in servAddr;	//sockaddr for the server address
	struct sockaddr_in a;
	
	int sockFd;						//actual socket
	int n,r;
	
	//Set the dnsheader pointer to point at the beggining of the buffer
	struct dnsheader *dns = (struct dnsheader *)&buf;
	bzero(buf, sizeof(buf));	//clear
	
	//fill id and flag info
	srand(time(NULL));			//random seed, using time(NULL)
	uint16_t ID_q = (uint16_t)rand()% 65536+1;	//2 byte ID 
	printf("Question ID:%x\n", ID_q);
	//printf("filling in dns header\n");
	dns->id = ID_q;
	dns->qr = 0; 
	dns->opcode = 0; 
	dns->aa = 0;
	dns->tc = 0;
	dns->rd = 1;
	dns->ra = 0; 
	dns->z = 0;
	dns->rcode = 0;
	
	dns->q_count = htons(1); 
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
	//printf("hostname:%s", hostname);
	//printf("\ncreating a query\n");

	//given unsiged char queryname, make it point to the address of buf after the dnsheader
	queryname = (unsigned char*)&buf[sizeof(struct dnsheader)];
	seperate(queryname, hostname);
	
	//printf("size of queryname %d", sizeof(queryname));
	//printf("\nformated string: %x\tdns->name: %x", queryname, dns->name);

	//given unsigned char queryinfo, make it point to the address of buf after dnsheader and queryname (including the null byte)
	queryinfo =(struct question*)&buf[sizeof(struct dnsheader) + (strlen((unsigned char*)queryname) + 1)];
	queryinfo->qtype = htons(1); 
	queryinfo->qclass = htons(1);
	
	//print(dns, "dns dump");
	
	//printf("creating socket\n");
	if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		perror("Error in socket():");
		exit(EXIT_FAILURE);
	}else{
		//printf("\nSocket Created");
	}

	
	//fill in remote server's info
	bzero(&servAddr, sizeof(servAddr));		//clear struct
	servAddr.sin_family = AF_INET;			//specify family
	servAddr.sin_port = htons(53);		//specify port
	inet_pton(AF_INET, argv[2], &servAddr.sin_addr);  
	
	//***************************************************************************************** send answer
	int length = sizeof(struct dnsheader)+strlen((unsigned char*)queryname)+sizeof(struct question)+1;
	n = sendto(sockFd,(char*)buf,length,0, (struct sockaddr*)&servAddr, sizeof(servAddr));
		
		//if n fails
		if (n < 0)
		{
			perror("udpclient.");
			fprintf(stdout,"Error occured during writing.\n");
			//fprintf(stdout,"Messages sent: %s, messages received: %s\n", msgS.b, msgR->b);
			fprintf(stdout,"Exiting.\n");
			exit(1);
		}else{
			//printf("\nRequest sent successfully");
		}	
	printf("Bytes sent: %d\n", n);
	//****************************************************************************************** recieve answer
	
	struct dnsheader *response = (struct dnsheader *)&buf;
	int serv_len = sizeof(servAddr);
	//the return size is irrelevent, can use anything as long as its enough
	r = recvfrom(sockFd, (char*)buf, 1024, 0, (struct sockaddr*)&servAddr, &serv_len);
		
		if (r < 0){
			perror("udpclient.");	
			fprintf(stdout,"Error occured during writing.\n");
			//fprintf(stdout,"Messages sent: %s, messages received: %s\n",msgS.b, msgR->b);
			fprintf(stdout,"Exiting.\n");	
			exit(1);
		}
	

	printf("Bytes recieved: %d\n", r);
	dns = (struct dnsheader*)&buf;
	uint16_t ID_a = (uint16_t)dns->id; 
	printf("Query ID: %x\n", ID_a);
	printf("Recursion supported:%d\n", dns->ra);
	printf("Query status:"); status(dns->rcode);
	printf("Number of Answers:%d\n", htons(dns->ans_count));
	printf("Number of Authorities:%d\n", htons(dns->auth_count));	
	printf("Number of Additional:%d\n", htons(dns->add_count));
	
	//****************************************************************************************** parse answer

	//calulate the offset for the answer
	//offset = sizeof(struct dnsheader)+strlen(queryname+1)+sizeof(struct question)+1;	//well this turned out to be wrong... -.-
	
	int ans_length;		//previous answer length
	int found = 0;		//found count
	int num_answers = htons(dns->ans_count);
	int offset;
	offset = sizeof(struct dnsheader);		
	offset += letter_counter+1;				
	offset += sizeof(struct question);		
	
	//printf("The offset is %d", offset);		//debugging
	answer = (struct record*)&buf[offset];		//the start of answer is located after sizeof(dnsheader, leter_counter (length of formated string) and question)
	
	//print((unsigned char*)answer, "Printing Record");		//debugging
	
	while(num_answers != 0){
		//printf("\nname:%x type:%x class:%d time_to_live:%x", ntohs(answer->name), ntohs(answer->type), ntohs(answer->class), ntohs(answer->ttl));	//debugging
		//find LENGTH, which is the length of original offset plus 3x uint16_t if you follow the struct of an answer and 1x uint32
		uint16_t *d_length = (uint16_t*)&buf[offset+sizeof(uint16_t)*3+sizeof(uint32_t)];
		
		//printf(" datalen:%x\n", ntohs(*d_length));	//debugging
		//the whole answer length which includes the name, type, class, ttl, data_len (length of data, integer) and d_length(actual data) in network order
		ans_length = sizeof(answer->name) + sizeof(answer->type) + sizeof(answer->class) + sizeof(answer->ttl) + sizeof(answer->data_len) + ntohs(*d_length); //+1
		
		if(ntohs(answer->class) == 1 && ntohs(answer->type) == 1){	//ip address
			answer = (struct record*)&buf[offset-4];
			unsigned char *data = answer->rdata;
			convert((int)answer->rdata);
			found++;
			offset = offset + ans_length;
			answer = (struct record*)&buf[offset];
		}else{														//cname
			offset = offset + ans_length;
			answer = (struct record*)&buf[offset];
			//print((unsigned char*)answer, "Printing answer");	//debugging
		}
		//printf("\ndata:%x \t answer:%x\n",answer, answer); 		//debugging
		num_answers--;
	}
	printf("Number of addresses found:%d", found);
	printf("\nEnd of processing.\n");    
	
	//EXIT, DONE!!!
	exit(1);
}
