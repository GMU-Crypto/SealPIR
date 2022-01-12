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
#define PORT 8080

using namespace std::chrono;
using namespace std;
using namespace seal;


inline unsigned int to_uint(char ch)
{
    // EDIT: multi-cast fix as per David Hammen's comment
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}

int main(int argc, char *argv[]) {

    cout << "Initializing PIR server..." << endl;

    uint64_t number_of_items = 1 << 12;
    uint64_t size_per_item = 288; // in bytes
    uint32_t N = 2048;

    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 12; 
    uint32_t d = 2;

    EncryptionParameters params(scheme_type::BFV);
    PirParams pir_params;

    // Generates all parameters
    cout << "Main: Generating all parameters" << endl;
    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    cout << "Main: Initializing the database (this may take some time) ..." << endl;

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
    cout << "Main: Initializing server and client" << endl;
    PIRServer server(params, pir_params);

    // Initialize PIR client....
    PIRClient client(params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    // Set galois key for client with id 0
    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    // Measure database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    cout << "Main: database pre processed " << endl;
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

/*
    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    //cout << "Main: FV index = " << index << ", FV offset = " << offset << endl; 
*/

    // Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query(index);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    //To marshall query to send over the network, you can use serialize/deserialize:
    //std::string query_ser = serialize_query(query);
    //PirQuery query2 = deserialize_query(d, 1, query_ser, CIPHER_SIZE);

    //NETWORKING - SERVER ROLE
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    //char *hello = "Hello from server";
       
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

   cout << "Waiting to receive query..." << endl;

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

/*
    std::string query_ser;
    query_ser = read( new_socket , buffer, 1024);
    printf("%s\n",buffer );
*/
    ///

    uint32_t msgLength;
    recv(new_socket,&msgLength,sizeof(uint32_t),0); // Receive the message length
    msgLength = ntohl(msgLength); // Ensure host system byte order

    //std::vector<uint8_t> pkt; // Allocate a receive buffer
    std::vector<unsigned char> pkt ;
    std::string temp ;
    pkt.resize(msgLength,0x00);

    recv(new_socket,&(pkt[0]),msgLength,0); // Receive the message data
    std::string query_ser;
    //query_ser.assign(&(pkt[0]),pkt.size()); // Convert message data to a string

    temp = { pkt.begin(), pkt.end() } ;

    //temp.assign( pkt.begin(), pkt.end() ) ;

    //temp.clear() ;
   //for( char c : temp ) temp += c ;

    ///
    //send(new_socket , hello , strlen(hello) , 0 );
    printf("Query Received\n");
    std::cout << "Query length: " <<msgLength <<endl;
    std::cout << "Actual query length: " <<temp.size() <<endl;
    std::cout << "Front:" << to_uint(temp.at(1000)) << endl;
    //std::cout << "Query: " <<temp <<endl;
    //std::string query_ser2 = serialize_query(query);
    PirQuery query2 = deserialize_query(d, 1, temp, CIPHER_SIZE);

    
    printf("Sending reply...\n");
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply(query2, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    std::string reply_ser = serialize_ciphertexts(reply);
    std::cout << "Reply length: " <<reply_ser.size() <<endl;

    //PirReply testreply = deserialize_ciphertexts(1,reply_ser, CIPHER_SIZE);

    uint32_t msgLength2 = reply_ser.size();
    uint32_t sndMsgLength = htonl(msgLength2); // Ensure network byte order

    send(new_socket,&sndMsgLength ,sizeof(uint32_t) ,MSG_CONFIRM); // Send the message length
    send(new_socket,reply_ser.c_str() ,msgLength2 ,MSG_CONFIRM); // Send the message data 
    std::cout << "Front:" << to_uint(reply_ser.at(1000)) << endl;
    printf("Reply sent.\n");

/*

    // Measure response extraction
    auto time_decode_s = chrono::high_resolution_clock::now();
    Plaintext result = client.decode_reply(reply);
    auto time_decode_e = chrono::high_resolution_clock::now();
    auto time_decode_us = duration_cast<microseconds>(time_decode_e - time_decode_s).count();

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, result, elems.data(), (N * logt) / 8);

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
            cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << endl;
            return -1;
        }
    }

    // Output results
    cout << "Main: PIR result correct!" << endl;
    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "Main: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;
    cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000 << " ms" << endl;
    cout << "Main: Reply num ciphertexts: " << reply.size() << endl;
*/
    return 0;
}
