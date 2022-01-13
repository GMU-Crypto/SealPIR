#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <seal/seal.h>
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include<strings.h>
#include<iostream>
#include<sys/types.h>
#include <arpa/inet.h>
#define PORT 12345

using namespace std::chrono;
using namespace std;
using namespace seal;


inline unsigned int to_uint(char ch)
{
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}

int main(int argc, char *argv[]) {

    cout << "Initializing PIR server..." << endl;

    //Setting up network socket - server role
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
       
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
       
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
       
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    cout << "(1) Creating database" << endl;
    uint64_t number_of_items = 1 << 16;
    uint64_t size_per_item = 1600; // in bytes
    uint32_t N = 2048;

    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 12; 
    uint32_t d = 2;

    EncryptionParameters params(scheme_type::BFV);
    PirParams pir_params;

    // Generates all parameters
    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    cout << "(1) Initializing the database (this may take some time) ..." << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

    random_device rd;
    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            //auto val = dbseed*dbfact % 3;
            db.get()[(i * size_per_item) + j] = 0;
            db_copy.get()[(i * size_per_item) + j] = 0;
        }
    }

    // Initialize PIR Server
    PIRServer server(params, pir_params);
    cout << "(1) Server initialized, waiting for connection..." << endl;

    //Step 2 Wait for connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "(2) Connection accepted" << endl;
    }



    // Receive Galois keys
    uint32_t msgLength;
    cout << "(2) receiving.... " << recv(new_socket,&msgLength,sizeof(uint32_t),0) << endl; // Receive the message length
    msgLength = ntohl(msgLength); // Ensure host system byte order
    std::cout << "(2) Galois keys length: " <<msgLength <<endl;

    std::vector<unsigned char> pkt ;
    std::string temp ;
    pkt.resize(msgLength,0x00);
    cout << "(2) About to recv Galois key" << endl;
    unsigned int recvd = 0;
    unsigned int this_recv = 0;
    do {
      cout << "(2) receiving... " << (this_recv = recv(new_socket,&(pkt[recvd]),msgLength-recvd,0)) << endl; // Receive the message data
      recvd += this_recv;
    } while (recvd < msgLength);
    cout << "(2) Galois keys received - total bytes: " << recvd << endl;

    temp = { pkt.begin(), pkt.end() } ;
    std::cout << "(2) Galois keys actual length: " <<temp.size() <<endl;
    std::cout << "(2) Correctness test for galois keys:" << to_uint(temp.at(100000)) << endl;
    GaloisKeys *g = deserialize_galoiskeys(temp);
    GaloisKeys galois_keys = *g;


    // Set galois key for client with id 0
    cout << "(2) Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    // Step 3 database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    cout << "(3) database pre processed " << endl;
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

/*    //Ready to receive query
    cout << "(3) Sending ready to receive query...";
    uint32_t testmsg = 1;
    uint32_t testMsgLength = htonl(testmsg);
    send(new_socket,&testMsgLength ,sizeof(uint32_t) ,0);
*/


    cout << "(4) Waiting to receive query..." << endl;


    recv(new_socket,&msgLength,sizeof(uint32_t),0); // Receive the message length
    msgLength = ntohl(msgLength); // Ensure host system byte order
    cout << "(4) Query length received: " << msgLength << endl;

    pkt.resize(msgLength,0x00);

    recvd = 0;
    do {
      this_recv = recv(new_socket,&(pkt[0]),msgLength-recvd,0); // Receive the message data
      recvd += this_recv;
    } while (recvd < msgLength);
    std::string query_ser;

    temp = { pkt.begin(), pkt.end() } ;

    std::cout << "(4) Query Received" << endl;
    std::cout << "(4) Query length: " <<msgLength <<endl;
    std::cout << "(4) Actual query length: " <<temp.size() <<endl;
    std::cout << "(4) Correctness test for query:" << to_uint(temp.at(1000)) << endl;
    PirQuery query = deserialize_query(d, 1, temp, CIPHER_SIZE);

    
    cout << "(5) Preparing reply..." << endl;
    PirReply reply = server.generate_reply(query, 0);
    std::string reply_ser = serialize_ciphertexts(reply);
    std::cout << "(5) Reply length: " <<reply_ser.size() <<endl;

    //PirReply testreply = deserialize_ciphertexts(1,reply_ser, CIPHER_SIZE);

    uint32_t msgLength2 = reply_ser.size();
    uint32_t sndMsgLength = htonl(msgLength2); // Ensure network byte order
    std::cout << "(5) Sending reply..." << endl;
    send(new_socket,&sndMsgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(new_socket,reply_ser.c_str() ,msgLength2 ,0); // Send the message data 
    std::cout << "(5) Correctness test for reply:" << to_uint(reply_ser.at(1000)) << endl;

    return 0;
}
