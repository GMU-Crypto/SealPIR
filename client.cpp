#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <seal/seal.h>
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
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

    cout << "Initializing PIR client..." << endl;

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

    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl; 

    // Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query(index);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    //To marshall query to send over the network, you can use serialize/deserialize:
    std::string query_ser = serialize_query(query);
    //PirQuery query2 = deserialize_query(d, 1, query_ser, CIPHER_SIZE);

    //NETWORKING - CLIENT ROLE
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    //char *hello = "Hello from client";
    //char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
       
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "10.193.124.164", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    //send(sock , query_ser.data() , strlen(query_ser.data()) , 0 );
    ///

    uint32_t msgLength = query_ser.size();
    uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order

    send(sock,&sndMsgLength ,sizeof(uint32_t) ,MSG_CONFIRM); // Send the message length
    send(sock,query_ser.c_str() ,msgLength ,MSG_CONFIRM); // Send the message data 
    std::cout << "Query length: " << query_ser.size() << endl;
    std::cout << "Front:" << to_uint(query_ser.at(1000)) << endl;

    ///
    //printf("Hello message sent\n");
    //valread = read( sock , buffer, 1024);
    //printf("%s\n",buffer );

    printf("Waiting for reply...\n");
    uint32_t msgLength2;
    recv(sock,&msgLength2,sizeof(uint32_t),0); // Receive the message length
    msgLength2 = ntohl(msgLength2); // Ensure host system byte order
    std::cout << "Reply length: " <<msgLength2 <<endl;

    //std::vector<uint8_t> pkt; // Allocate a receive buffer
    std::vector<unsigned char> pkt ;
    std::string temp ;
    pkt.resize(msgLength2,0x00);

    recv(sock,&(pkt[0]),msgLength2,0); // Receive the message data
    //std::string query_ser;
    //query_ser.assign(&(pkt[0]),pkt.size()); // Convert message data to a string

    temp = { pkt.begin(), pkt.end() } ;

    printf("Reply Received\n");
    std::cout << "Actual reply length: " <<temp.size() <<endl;
    std::cout << "Front:" << to_uint(temp.at(1000)) << endl;
    //std::cout << "Query: " <<temp <<endl;
    //std::string query_ser2 = serialize_query(query);
    PirReply reply = deserialize_ciphertexts(1, temp, CIPHER_SIZE);  

/*
    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply(query, 0);
    auto time_server_e = high_resolution_clock::now();
    */

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
    //cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
    //     << endl;
    cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000 << " ms" << endl;
    cout << "Main: Reply num ciphertexts: " << reply.size() << endl;

    return 0;
}
