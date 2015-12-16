#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "dns.h"




int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response, struct sockaddr_storage * nameservers, int nameserver_count);
typedef struct addrinfo saddrinfo;
typedef struct sockaddr_storage sss;
int root_server_count;
sss root_servers[255];
static int debug = 0;
cache dnscache;
uint32_t start, stop;

void set_ttl(uint8_t *response, uint32_t timestamp) {
    struct dns_hdr * header = (struct dns_hdr *) response;
    uint8_t * answer_ptr = response + sizeof (struct dns_hdr);

    // now answer_ptr points at the first question.
    int question_count = ntohs(header->q_count);
    int answer_count = ntohs(header->a_count);
    int auth_count = ntohs(header->auth_count);
    int other_count = ntohs(header->other_count);

    // skip questions
    int q;
    for (q = 0; q < question_count; q++) {
        char string_name[255];
        memset(string_name, 0, 255);
        int size = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += size;
        answer_ptr += 4;
    }
    uint8_t * bookmark = answer_ptr;
    int a, minflag = 0, minttl;
    for (a = 0; a < answer_count; a++) {
        char string_name[255];
        int dnsnamelen = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += dnsnamelen;

        struct dns_rr* rr = (struct dns_rr*) answer_ptr;
        answer_ptr += sizeof (struct dns_rr);

        if (htons(rr->type) == RECTYPE_A) {
                if (minflag == 0) {
                    minttl = ntohl(rr->ttl);
                    minflag = 1;
                } else {
                    unsigned int temp;
                    temp = ntohl(rr->ttl);
                    if (temp < minttl) {
                        minttl = temp;
                    }
                }
            
        }
        else if (htons(rr->type) == RECTYPE_CNAME) {
                if (minflag == 0) {
                    minttl = ntohl(rr->ttl);
                    minflag = 1;
                } else {
                    unsigned int temp;
                    temp = ntohl(rr->ttl);
                    if (temp < minttl) {
                        minttl = temp;
                    }
                }
        }
        else if (htons(rr->type) == RECTYPE_AAAA) {
                if (minflag == 0) {
                    minttl = ntohl(rr->ttl);
                    minflag = 1;
                } else {
                    unsigned int temp;
                    temp = ntohl(rr->ttl);
                    if (temp < minttl) {
                        minttl = temp;
                    }
                }
        }
        answer_ptr += htons(rr->datalen);
    }

    answer_ptr = bookmark;
    uint32_t initial_time = timestamp - minttl;
    uint32_t current_time;
    time(&current_time);

    for (a = 0; a < answer_count; a++) {

        char string_name[255];
        int dnsnamelen = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += dnsnamelen;

        struct dns_rr* rr = (struct dns_rr*) answer_ptr;
        answer_ptr += sizeof (struct dns_rr);

        if (htons(rr->type) == RECTYPE_A) {
                uint32_t ttl = ntohl(rr->ttl);
                rr->ttl= htonl(ttl+initial_time-current_time);
        }// AAAA record
        else if (htons(rr->type) == RECTYPE_CNAME) {
                uint32_t ttl = ntohl(rr->ttl);
                rr->ttl= htonl(ttl+initial_time-current_time);
        }
        else if (htons(rr->type) == RECTYPE_AAAA) {
                uint32_t ttl = ntohl(rr->ttl);
                rr->ttl= htonl(ttl+initial_time-current_time);
        }
        answer_ptr += htons(rr->datalen);
    }
}

int searchcache(char *hostname, uint8_t *response) {
    int i;
    for (i = 0; i < dnscache.max; i++) {
        if (dnscache.table[i] != NULL) {
            if (strcmp(hostname, dnscache.table[i]->hostname) == 0) {
                uint32_t current_time;
                time(&current_time);
                
                if (dnscache.table[i]->timestamp > current_time) {//ttl not expired
                    set_ttl(dnscache.table[i]->response, dnscache.table[i]->timestamp);
                    memcpy(response, dnscache.table[i]->response, dnscache.table[i]->size);
                    return dnscache.table[i]->size;
                } else {//ttl has expired.
                    free(dnscache.table[i]);
                    dnscache.table[i] = NULL;
                    if (i == dnscache.max) {
                        dnscache.max--;
                    }
                    return 0;
                }
            }
        }
    }
    return 0;
}

uint32_t set_timestamp(uint8_t *response) {
    struct dns_hdr * header = (struct dns_hdr *) response;
    uint8_t * answer_ptr = response + sizeof (struct dns_hdr);

    // now answer_ptr points at the first question.
    int id = ntohs(header->id);
    int question_count = ntohs(header->q_count);
    int answer_count = ntohs(header->a_count);
    int auth_count = ntohs(header->auth_count);
    int other_count = ntohs(header->other_count);

    // skip questions
    int q;
    for (q = 0; q < question_count; q++) {
        char string_name[255];
        memset(string_name, 0, 255);
        int size = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += size;
        answer_ptr += 4;
    }

    int a, ns_count = 0;
    unsigned int timestamp;
    int minflag = 0;
    for (a = 0; a < answer_count; a++) {
        // first the name this answer is referring to
        char string_name[255];
        int dnsnamelen = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += dnsnamelen;
        // then fixed part of the RR record
        struct dns_rr* rr = (struct dns_rr*) answer_ptr;
        answer_ptr += sizeof (struct dns_rr);
        //A record
        if (htons(rr->type) == RECTYPE_A) {
                if (minflag == 0) {
                    timestamp = ntohl(rr->ttl);
                    minflag = 1;
                } else {
                    unsigned int temp;
                    temp = ntohl(rr->ttl);
                    if (temp < timestamp) {
                        timestamp = temp;
                    }
                }
            
        }
        else if (htons(rr->type) == RECTYPE_CNAME) {
                if (minflag == 0) {
                    timestamp = ntohl(rr->ttl);
                    minflag = 1;
                } else {
                    unsigned int temp;
                    temp = ntohl(rr->ttl);
                    if (temp < timestamp) {
                        timestamp = temp;
                    }
                }
            
        }
        else if (htons(rr->type) == RECTYPE_AAAA) {
                if (minflag == 0) {
                    timestamp = ntohl(rr->ttl);
                    minflag = 1;
                } else {
                    unsigned int temp;
                    temp = ntohl(rr->ttl);
                    if (temp < timestamp) {
                        timestamp = temp;
                    }
                }
            
        }
        answer_ptr += htons(rr->datalen);
    }
    return timestamp;
}

void usage() {
    printf("Usage: hw4 [-d] [-p port]\n\t-d: debug\n\t-p: port\n");
    exit(1);
}

/* returns: true if answer found, false if not.
 * side effect: on answer found, populate result with ip address.
 */
int extract_answer(uint8_t * response, sss * result) {

    // parse the response to get our answer
    struct dns_hdr * header = (struct dns_hdr *) response;
    uint8_t * answer_ptr = response + sizeof (struct dns_hdr);

    memset(result, 0, sizeof (sss));

    // now answer_ptr points at the first question.
    int question_count = ntohs(header->q_count);
    int answer_count = ntohs(header->a_count);
    int auth_count = ntohs(header->auth_count);
    int other_count = ntohs(header->other_count);


    if (debug)
        printf("in extract answer\n");
    // if we didn't get an answer, just quit
    if (answer_count == 0) {
        return 0;
    }

    // skip questions
    int q;
    for (q = 0; q < question_count; q++) {
        char string_name[255];
        memset(string_name, 0, 255);
        int size = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += size;
        answer_ptr += 4;
    }

    if (debug)
        printf("Got %d+%d+%d=%d resource records total.\n", answer_count, auth_count, other_count, answer_count + auth_count + other_count);
    if (answer_count + auth_count + other_count > 50) {
        printf("ERROR: got a corrupt packet\n");
        return -1;
    }

    /*
     * accumulate authoritative nameservers to a list so we can recurse through them
     */
    int a;
    for (a = 0; a < answer_count; a++) {
        // first the name this answer is referring to
        char string_name[255];
        int dnsnamelen = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += dnsnamelen;

        // then fixed part of the RR record
        struct dns_rr* rr = (struct dns_rr*) answer_ptr;
        answer_ptr += sizeof (struct dns_rr);

        //A record
        if (htons(rr->type) == RECTYPE_A) {
            if (debug)
                printf("The name %s resolves to IP addr: %s\n",
                    string_name,
                    inet_ntoa(*((struct in_addr *) answer_ptr)));
            //if it's in the answer section, then we got our answer
            if (a < answer_count) {
                ((struct sockaddr_in*) result)->sin_family = AF_INET;
                ((struct sockaddr_in*) result)->sin_addr = *((struct in_addr *) answer_ptr);
                return 1;
            }

        }//CNAME record
        else if (htons(rr->type) == RECTYPE_CNAME) {
            char ns_string[255];
            int ns_len = from_dns_style(response, answer_ptr, ns_string);
            if (debug)
                printf("The name %s is also known as %s.\n",
                    string_name, ns_string);

        }// AAAA record
        else if (htons(rr->type) == RECTYPE_AAAA) {
            if (debug) {
                char printbuf[INET6_ADDRSTRLEN];
                printf("The name %s resolves to IP addr: %s\n",
                        string_name,
                        inet_ntop(AF_INET6, answer_ptr, printbuf, INET6_ADDRSTRLEN));
            }
            ((struct sockaddr_in6*) result)->sin6_family = AF_INET6;
            ((struct sockaddr_in6*) result)->sin6_addr = *((struct in6_addr *) answer_ptr);
            return 1;

        } else {
            if (debug)
                printf("got unknown record type %hu\n", htons(rr->type));
        }
        answer_ptr += htons(rr->datalen);
    }
    return 0;
}

// wrapper for inet_ntop that takes a sockaddr_storage as argument

const char * ss_ntop(struct sockaddr_storage * ss, char * dst, int dstlen) {
    void * addr;
    if (ss->ss_family == AF_INET)
        addr = &(((struct sockaddr_in*) ss)->sin_addr);
    else if (ss->ss_family == AF_INET6)
        addr = &(((struct sockaddr_in6*) ss)->sin6_addr);
    else {
        if (debug)
            printf("error parsing ip address\n");
        return NULL;
    }
    return inet_ntop(ss->ss_family, addr, dst, dstlen);
}

/*
 * wrapper for inet_pton that detects a valid ipv4/ipv6 string and returns it in pointer to
 * sockaddr_storage dst
 *
 * return value is consistent with inet_pton
 */
int ss_pton(const char * src, void * dst) {//ftiaxnei ti lista root_servers me swstes dieuthinseis kai family kai alla
    unsigned char buf[sizeof (struct in6_addr)];
    int r;
    r = inet_pton(AF_INET, src, buf);
    if (r == 1) {//if it is IPv4 
        char printbuf[INET6_ADDRSTRLEN];
        struct sockaddr_in6 * out = (struct sockaddr_in6*) dst;
        // for socket purposes, we need a v4-mapped ipv6 address
        unsigned char * mapped_dst = (void*) &out->sin6_addr;
        //take the first 4 bytes of buf and put them in the last 4
        //of the return value
        memcpy(mapped_dst + 12, buf, 4);
        // set the first 10 bytes to 0
        memset(mapped_dst, 0, 10);
        // set the next 2 bytes to 0xff
        memset(mapped_dst + 10, 0xff, 2);
        out->sin6_family = AF_INET6;
        return 1;
    }
    r = inet_pton(AF_INET6, src, buf); //if it is IPv6
    if (r == 1) {
        struct sockaddr_in6 * out = (struct sockaddr_in6*) dst;
        out->sin6_family = AF_INET6;
        out->sin6_addr = *((struct in6_addr*) buf);
        return 1;
    }
    return r;
}

void read_server_file() {//doulevei se synergasia me tin sss_pton
    root_server_count = 0;
    char addr[25];

    FILE *f = fopen("root-servers.txt", "r");
    while (fscanf(f, " %s ", addr) > 0) {//for all entries on root-servers.txt file
        ss_pton(addr, &root_servers[root_server_count++]);
    }
}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname, int qtype) {

    memset(query, 0, max_query);
    // does the hostname actually look like an IP address? If so, make
    // it a reverse lookup. 
    in_addr_t rev_addr = inet_addr(hostname);
    if (rev_addr != INADDR_NONE) {
        static char reverse_name[255];
        sprintf(reverse_name, "%d.%d.%d.%d.in-addr.arpa",
                (rev_addr & 0xff000000) >> 24,
                (rev_addr & 0xff0000) >> 16,
                (rev_addr & 0xff00) >> 8,
                (rev_addr & 0xff));
        hostname = reverse_name;
    }
    // first part of the query is a fixed size header
    struct dns_hdr *hdr = (struct dns_hdr*) query;
    // generate a random 16-bit number for session
    uint16_t query_id = (uint16_t) (random() & 0xffff);
    hdr->id = htons(query_id);
    // set header flags to request recursive query
    hdr->flags = htons(0x0100);
    // 1 question, no answers or other records
    hdr->q_count = htons(1);
    // add the name
    int query_len = sizeof (struct dns_hdr);
    int name_len = to_dns_style(hostname, query + query_len);
    query_len += name_len;
    // now the query type: A/AAAA or PTR. 
    uint16_t *type = (uint16_t*) (query + query_len);
    if (rev_addr != INADDR_NONE) {
        *type = htons(12);
    } else {
        *type = htons(qtype);
    }
    query_len += 2;
    //finally the class: INET
    uint16_t *class = (uint16_t*) (query + query_len);
    *class = htons(1);
    query_len += 2;
    return query_len;
}

int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response,
        struct sockaddr_storage * nameservers, int nameserver_count) {
    //Assume that we're getting no more than 20 NS responses
    char recd_ns_name[20][255];
    struct sockaddr_storage recd_ns_ips[20];
    int recd_ns_count = 0;
    int recd_ip_count = 0; // additional records
    int response_size = 0;
    // if an entry in recd_ns_ips is 0.0.0.0, we treat it as unassigned
    memset(recd_ns_ips, 0, sizeof (recd_ns_ips));
    memset(recd_ns_name, 0, 20 * 255);
    int retries = 5;

    memset(response, 0, UDP_RECV_SIZE);

    if (debug)
        printf("resolve name called with packet size %d\n", packet_size);

    int chosen = random() % nameserver_count;
    struct sockaddr_storage * chosen_ns = &nameservers[chosen];
    if (debug) {
        printf("\nAsking for record using server %d out of %d\n", chosen, nameserver_count);
    }

    /* using sockaddr to actually send a packet, so make sure the 
     * port is set
     */
    if (debug)
        printf("ss family: %d\n", chosen_ns->ss_family);
    if (chosen_ns->ss_family == AF_INET)
        ((struct sockaddr_in *) chosen_ns)->sin_port = htons(53);
    else if (chosen_ns->ss_family == AF_INET6)
        ((struct sockaddr_in6 *) chosen_ns)->sin6_port = htons(53);
    else {
        // this can happen during recursion if a NS w/o a glue record
        // doesn't resolve properly
        if (debug)
            printf("ss_family not set\n");
    }

    // parse the response to get our answer
    struct dns_hdr * request_header = (struct dns_hdr *) request;
    uint8_t * request_ptr = request + sizeof (struct dns_hdr);


    // now answer_ptr points at the first question.
    int req_id = ntohs(request_header->id);
    int req_question_count = ntohs(request_header->q_count);
    int req_answer_count = ntohs(request_header->a_count);
    int req_auth_count = ntohs(request_header->auth_count);
    int req_other_count = ntohs(request_header->other_count);
    printf("Got %d+%d+%d+%d=%d resource records total.\n", req_answer_count, req_question_count, req_auth_count,
            req_other_count, req_answer_count + req_question_count + req_auth_count + req_other_count);

    request_header->flags ^= (-0 ^ request_header->flags) & (1 << 0); //changed recursion bit to 0 if it was 1

    int v;
    char string_name[255];
    for (v = 0; v < req_question_count; v++) {
        memset(string_name, 0, 255);
        int size = from_dns_style(response, request_ptr, string_name);
        request_ptr += size;
        struct dns_query_section* qs = (struct dns_query_section*) request_ptr;
        request_ptr += sizeof (struct dns_query_section);
        printf("Requesting about: %s - with type %d and class %d\n", string_name, ntohs(qs->type), ntohs(qs->class));
    }
    uint8_t new_response[UDP_RECV_SIZE];
    int new_size = searchcache(string_name, new_response);
    if (new_size > 0) {
        printf("HIT!\n");
        struct dns_hdr * new_header = (struct dns_hdr *) new_response;
        new_header->id = htons(req_id);
        uint8_t * new_ptr = new_response + sizeof (struct dns_hdr);

        memcpy(response, new_response, new_size);
        return new_size;
    }


    int send_count = sendto(sock, request, packet_size, 0,
            (struct sockaddr *) chosen_ns, sizeof (struct sockaddr_in6));
    if (send_count < 0) {
        perror("Send failed");
        exit(1);
    }

    // await the response - not calling recvfrom, don't care who is responding
    response_size = recv(sock, response, UDP_RECV_SIZE, 0);
    // discard anything that comes in as a query instead of a response
    if ((response_size > 0) && ((ntohs(((struct dns_hdr *) response)->flags) & 0x8000) == 0)) {
        if (debug) {
            printf("flags: 0x%x\n", ntohs(((struct dns_hdr *) response)->flags) & 0x8000);
            printf("received a query while expecting a response\n");
        }
    }
    if (debug) printf("response size: %d\n", response_size);

    // parse the response to get our answer
    struct dns_hdr * header = (struct dns_hdr *) response;
    uint8_t * answer_ptr = response + sizeof (struct dns_hdr);

    // now answer_ptr points at the first question.
    int id = ntohs(header->id);
    int question_count = ntohs(header->q_count);
    int answer_count = ntohs(header->a_count);
    int auth_count = ntohs(header->auth_count);
    int other_count = ntohs(header->other_count);

    // skip questions
    int q;
    for (q = 0; q < question_count; q++) {
        char string_name[255];
        memset(string_name, 0, 255);
        int size = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += size;
        answer_ptr += 4;
    }
    if (debug)
        printf("Got %d+%d+%d=%d resource records total.\n", answer_count, auth_count, other_count, answer_count + auth_count + other_count);
    if (answer_count + auth_count + other_count > 50) {
        printf("ERROR: got a corrupt packet\n");
        return -1;
    }
    /*
     * iterate through answer, authoritative, and additional records
     */
    if (debug) printf("Answer count: %d\n", answer_count);
    int a, ns_count = 0;
    int cnameflag = 0;
    char cname[250];
    unsigned int timestamp;
    int minflag = 0;
    for (a = 0; a < answer_count + auth_count + other_count; a++) {
        // first the name this answer is referring to
        char string_name[255];
        int dnsnamelen = from_dns_style(response, answer_ptr, string_name);
        answer_ptr += dnsnamelen;
        // then fixed part of the RR record
        struct dns_rr* rr = (struct dns_rr*) answer_ptr;
        answer_ptr += sizeof (struct dns_rr);
        //A record
        if (htons(rr->type) == RECTYPE_A) {
            if (debug)
                printf("The name %s resolves to IP addr: %s\n",
                    string_name,
                    inet_ntoa(*((struct in_addr *) answer_ptr)));
            if (answer_count == 0 && a >= auth_count) {
                ss_pton(inet_ntoa(*((struct in_addr *) answer_ptr)), &recd_ns_ips[ns_count++]);
            } else if (answer_count > 0) {
                if (debug) printf("Found answer!");
            }
        }//NS record
        else if (htons(rr->type) == RECTYPE_NS) {
            int size1 = from_dns_style(response, answer_ptr, recd_ns_name[recd_ns_count]);
            if (debug)
                printf("The name %s can be resolved by NS: %s\n",
                    string_name, recd_ns_name[recd_ns_count]);
            recd_ns_count++;
        }//CNAME record
        else if (htons(rr->type) == RECTYPE_CNAME) {

            char ns_string[255];

            int ns_len = from_dns_style(response, answer_ptr, ns_string);
            if (cnameflag == 0) {
                memcpy(cname, ns_string, strlen(ns_string) + 1);
            }
            cnameflag = 1;
            if (debug)
                printf("The name %s is also known as %s.\n",
                    string_name, ns_string);
        }// SOA record
        else if (htons(rr->type) == RECTYPE_SOA) {
            if (debug)
                printf("Ignoring SOA record\n");
        }// AAAA record
        else if (htons(rr->type) == RECTYPE_AAAA) {
            if (debug) {
                char printbuf[INET6_ADDRSTRLEN];
                printf("The name %s resolves to IP addr: %s\n",
                        string_name,
                        inet_ntop(AF_INET6, answer_ptr, printbuf, INET6_ADDRSTRLEN));
                if (answer_count == 0 && a >= auth_count) {
                    ss_pton(inet_ntop(AF_INET6, answer_ptr, printbuf, INET6_ADDRSTRLEN), &recd_ns_ips[ns_count++]);
                } else if (answer_count > 0) printf("YO!!\n");
            }
        } else {
            if (debug)
                printf("got unknown record type %hu\n", htons(rr->type));
        }
        answer_ptr += htons(rr->datalen);
    }
    if (answer_count == 0) {
        if (ns_count > 0) {
            response_size = resolve_name(sock, request, packet_size, response, recd_ns_ips, ns_count);
        } else {
            chosen = random() % recd_ns_count;
            uint8_t new_request[UDP_RECV_SIZE];
            uint8_t new_response[UDP_RECV_SIZE];
            int request_size = construct_query(new_request, UDP_RECV_SIZE, recd_ns_name[chosen], 1);
            int new_response_size = resolve_name(sock, new_request, request_size, new_response, root_servers, root_server_count);
            if (extract_answer(new_response, recd_ns_ips)) {
                response_size = resolve_name(sock, request, packet_size, response, recd_ns_ips, 1);
            }

        }
    }
    if (cnameflag == 1 && answer_count != 0) { //CNAME RESTART
        uint8_t new_response[UDP_RECV_SIZE];
        memset(new_response, 0, UDP_RECV_SIZE);
        uint8_t final_response[UDP_RECV_SIZE];
        memset(final_response, 0, UDP_RECV_SIZE);
        int new_response_size;

        int request_size = construct_query(request, UDP_RECV_SIZE, cname, 1);
        new_response_size = resolve_name(sock, request, request_size, new_response, root_servers, root_server_count);

        uint8_t * response_ptr = response + sizeof (struct dns_hdr);

        struct dns_hdr * new_response_header = (struct dns_hdr *) new_response;
        uint8_t * new_response_ptr = new_response + sizeof (struct dns_hdr);


        int new_question_count = ntohs(new_response_header->q_count);
        int new_answer_count = ntohs(new_response_header->a_count);

        header->a_count = htons(answer_count + new_answer_count);

        int v, q;
        for (q = 0; q < question_count; q++) {
            char string_name[255];
            memset(string_name, 0, 255);
            int size = from_dns_style(response, response_ptr, string_name);
            response_ptr += size;
            response_ptr += 4;
        }

        for (v = 0; v < answer_count; v++) {
            char string_name[255];
            int dnsnamelen = from_dns_style(response, response_ptr, string_name);
            response_ptr += dnsnamelen;
            struct dns_rr* rr = (struct dns_rr*) response_ptr;
            response_ptr += sizeof (struct dns_rr);
            response_ptr += htons(rr->datalen);
        }
        int counter = response_ptr - response;
        memcpy(final_response, response, counter);

        for (q = 0; q < new_question_count; q++) {
            char string_name[255];
            memset(string_name, 0, 255);
            int size = from_dns_style(response, new_response_ptr, string_name);
            new_response_ptr += size;
            new_response_ptr += 4;
        }

        int counter1 = 0;
        for (v = 0; v < new_answer_count; v++) {
            char string_name[255];
            int dnsnamelen = from_dns_style(new_response, new_response_ptr, string_name);
            new_response_ptr += dnsnamelen;
            counter1 += dnsnamelen;
            struct dns_rr* rr = (struct dns_rr*) new_response_ptr;
            new_response_ptr += sizeof (struct dns_rr);
            counter1 += sizeof (struct dns_rr);
            new_response_ptr += htons(rr->datalen);
            counter1 += htons(rr->datalen);
        }
        memcpy(final_response + counter, new_response_ptr - counter1, counter1);
        memcpy(final_response + counter + counter1, response_ptr, response_size - counter);

        memcpy(response, final_response, sizeof (final_response));
        response_size = response_size + counter1 + 1;
    }

    dnscache.table[dnscache.max] = malloc(sizeof (cache_entry));
    strcpy(dnscache.table[dnscache.max]->hostname, string_name);
    memcpy(dnscache.table[dnscache.max]->response, response, response_size);
    dnscache.table[dnscache.max]->size = response_size;
    uint32_t current_time;
    time(&current_time);
    dnscache.table[dnscache.max]->timestamp = set_timestamp(response) + current_time;
    dnscache.max++;
    return response_size;
}

int main(int argc, char ** argv) {
    int port_num = 5454;
    int sockfd;
    struct sockaddr_in6 server_address;
    struct dns_hdr * header = NULL;
    char * question_domain = NULL;
    char client_ip[INET6_ADDRSTRLEN];
    char *optString = "dp";
    struct timeval timeout;

    int opt = getopt(argc, argv, optString);

    while (opt != -1) {
        switch (opt) {
            case 'd':
                debug = 1;
                printf("Debug mode\n");
                break;
            case 'p':
                port_num = atoi(argv[optind]);
                break;
            case '?':
                usage();
                break;
        }
        opt = getopt(argc, argv, optString);
    }
    read_server_file();
    //Create socket as DNS Server
    printf("Creating socket on port: %d\n", port_num);
    sockfd = socket(AF_INET6, SOCK_DGRAM, 0); //create UDP socket
    if (sockfd < 0) {
        perror("Unable to create socket");
        return -1;
    }
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout));

    int on = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

    memset(&server_address, 0, sizeof (server_address));
    server_address.sin6_family = AF_INET6;
    server_address.sin6_addr = in6addr_any;
    server_address.sin6_port = htons(port_num);
    if (bind(sockfd, (struct sockaddr *) &server_address, sizeof (server_address)) < 0) {
        perror("Unable to bind");
        return -1;
    }
    if (debug) printf("Bind successful\n");

    socklen_t addrlen = sizeof (struct sockaddr_in6);
    struct sockaddr_in6 client_address;
    uint8_t request[UDP_RECV_SIZE];
    uint8_t response[UDP_RECV_SIZE];
    int packet_size;
    if (debug)
        printf("Waiting for query...\n");

    dnscache.max = 0;
    int q;
    for (q = 0; q < 250/*sizeof(dnscache.table)*/; q++) {
        dnscache.table[q] = NULL;
    }
    time(&start);
    while (1) {
        if ((packet_size = recvfrom(sockfd, request, UDP_RECV_SIZE, 0, (struct sockaddr *) &client_address, &addrlen)) < 0) {
            perror("recvfrom error");
            printf("timed out... %d\n", packet_size);
            continue;
        }
        if (debug) printf("received request of size %d\n", packet_size);


        if (packet_size < (int) (sizeof (struct dns_hdr) + sizeof (struct dns_query_section))) {
            perror("Receive invalid DNS request");
            continue;
        }

        header = (struct dns_hdr *) response;

        packet_size = resolve_name(sockfd, request, packet_size, response, root_servers, root_server_count);
        if (packet_size <= 0) {
            perror("failed to receive any answer (unexpected!)");
            continue;
        }
        if (debug)
            printf("outgoing packet size: %d\n", packet_size);

        //send the response to client
        int sent_count = sendto(sockfd, response, packet_size, 0, (struct sockaddr*) &client_address, addrlen);
        if (debug)
            printf("Waiting for query...\n");
        time(&stop);

    }

    return 0;
}

