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
#define PORT 12345

using namespace std::chrono;
using namespace std;
using namespace seal;

inline unsigned int to_uint(char ch)
{
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}

int main(int argc, char *argv[]) {

    cout << "Initializing PIR client..." << endl;

    //Setting up network socket - client role
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
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
   


    cout << "(1) Creating database (for correctness comparison)" << endl;

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

    cout << "(1)  Initializing the database (this may take some time) ..." << endl;

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

    // Initialize PIR Server (for comparison)
    PIRServer server(params, pir_params);

    // Initialize PIR client....
    PIRClient client(params, pir_params);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    else 
    {
        cout << "(2) Connected to server" << endl;
    }


    GaloisKeys galois_keys = client.generate_galois_keys();
    std::string  galois_keys_ser = serialize_galoiskeys(galois_keys);

    // Send Galois keys to server
    uint32_t msgLength = galois_keys_ser.size();
    uint32_t sndMsgLength = htonl(msgLength); // Ensure network byte order

    std::cout << "(2) Sending Galois key..." << endl;

    cout << "(2) sending... " << send(sock,&sndMsgLength ,sizeof(uint32_t) ,0) << endl; // Send the message length
    std::cout << "(2) Galois keys length: " << galois_keys_ser.size() << endl;
    cout << "(2) About to send Galois key " << endl;
    
    cout << "(2) sending... " << send(sock,galois_keys_ser.c_str() ,msgLength ,0) << endl; // Send the message data 
    std::cout << "(2) Correctness test for galois keys:" << to_uint(galois_keys_ser.at(100000)) << endl;


    // Step 3 database setup
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    cout << "(3) database pre processed " << endl;



/*
    printf("Confirming ready to send query...\n");
    uint32_t testmsg;
    recv(sock,&testmsg,sizeof(uint32_t),0); // Receive the message length
    testmsg = ntohl(testmsg); // Ensure host system byte order
    std::cout << "Confirmation: " <<testmsg <<endl;
*/
    // Measure query generation
    cout << "(4) Generating query..." << endl;
    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    PirQuery query = client.generate_query(index);
    std::string query_ser = serialize_query(query);
 
    msgLength = query_ser.size();
    sndMsgLength = htonl(msgLength); // Ensure network byte order

    std::cout << "(4) Sending query: " << endl;
    send(sock,&sndMsgLength ,sizeof(uint32_t) ,0); // Send the message length
    send(sock,query_ser.c_str() ,msgLength ,0); // Send the message data 
    std::cout << "(4) Query length: " << query_ser.size() << endl;
    std::cout << "(4) Correctness test for query:" << to_uint(query_ser.at(1000)) << endl;


    std::cout << "(5) Waiting for reply..." << endl;
    uint32_t msgLength2;
    recv(sock,&msgLength2,sizeof(uint32_t),0); // Receive the message length
    msgLength2 = ntohl(msgLength2); // Ensure host system byte order
    std::cout << "(5) Reply length: " <<msgLength2 <<endl;

    std::vector<unsigned char> pkt ;
    std::string temp ;
    pkt.resize(msgLength2,0x00);

    recv(sock,&(pkt[0]),msgLength2,0); // Receive the message data
 
    temp = { pkt.begin(), pkt.end() } ;

    std::cout << "(5) Actual reply length: " <<temp.size() <<endl;
    std::cout << "(5) Correctness test for reply:" << to_uint(temp.at(1000)) << endl;

    PirReply reply = deserialize_ciphertexts(1, temp, CIPHER_SIZE);  
    std::cout << "(5) - a" << endl;

    Plaintext result = client.decode_reply(reply);

    std::cout << "(5) - b" << endl;
    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, result, elems.data(), (N * logt) / 8);
    std::cout << "(5) - c" << endl;
    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
            cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << endl;
            return -1;
        }
    }

    return 0;
}
