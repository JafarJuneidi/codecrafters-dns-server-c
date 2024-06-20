#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 512

void encode_string(unsigned char *buffer, size_t *index, char *name) {
  size_t name_len = strlen(name);
  char *dot_pos = strchr(name, '.');
  buffer[(*index)++] = dot_pos - name;
  for (size_t i = 0; i < name_len; ++i) {
    if (name[i] == '.') {
      buffer[(*index)++] = name_len - i - 1;
      continue;
    }
    buffer[(*index)++] = name[i];
  }
  buffer[(*index)++] = 0x00;
}

char add_header(unsigned char *response, unsigned char *buffer) {
  // big endian (start putting the bigger address)
  // low address          high address
  // [MSB, ....................., LSB]

  // ID 8 bits
  response[0] = buffer[0];
  // ID 8 bits
  response[1] = buffer[1];
  // QR 1 bit, OPCODE 4 bits, AA 1 bit, TC 1 bit, RD 1 bit
  // response[2] = buffer[2] | 0x80;
  response[2] = 0;
  // RA 1 bit, Z 3 bits, RCODE 4 bits
  // response[3] = (buffer[2] & 0b01111000) == 0 ? 0 : 0x04;
  response[3] = 0;
  // QDCOUNT 8 bits
  response[4] = buffer[4];
  // QDCOUNT 8 bits
  // response[5] = buffer[5];
  response[5] = 0x01;
  // ANCOUNT 8 bits
  response[6] = buffer[6];
  // ANCOUNT 8 bits
  // response[7] = buffer[5]; // Same as question count
  response[7] = 0x00;
  // NSCOUNT 8 bits
  response[8] = buffer[8];
  // NSCOUNT 8 bits
  response[9] = buffer[9];
  // ARCOUNT 8 bits
  response[10] = buffer[10];
  // ARCOUNT 8 bits
  response[11] = buffer[11];

  return buffer[5];
}

void add_question(unsigned char *response, const unsigned char *buffer,
                  size_t *request_index, size_t *response_index) {
  const unsigned char *ptr = (buffer + *request_index);
  // Handle DNS name
  int flag = 0;
  while (*ptr != 0) {
    if ((*ptr & 0xC0) == 0xC0) { // Pointer to another location
      size_t offset = ((*ptr & 0x3F) << 8) | *(ptr + 1);
      ptr = buffer + offset;
      *request_index += 2;
      flag = 1;
      continue;
    }
    size_t label_length = *ptr + 1;
    memcpy(response + *response_index, ptr, label_length);
    ptr += label_length;
    *response_index += label_length;
    if (!flag) {
      *request_index += label_length;
    }
  }

  // Copy the null byte for the end of the name
  response[(*response_index)++] = 0x00;
  if (!flag) {
    *request_index += 1;
  }

  *request_index += 4;

  response[(*response_index)++] = 0x00;
  response[(*response_index)++] = 0x01;
  response[(*response_index)++] = 0x00;
  response[(*response_index)++] = 0x01;
}

void add_answer(unsigned char *response, size_t *response_index) {
  size_t index = 12;
  size_t old_response_index = *response_index;
  while (index < old_response_index) {
    size_t length = strlen((char *)response + index) + 5;

    memcpy(response + *response_index, response + index, length);

    *response_index += length;
    index += length;

    response[(*response_index)++] = 0x00;
    response[(*response_index)++] = 0x00;
    response[(*response_index)++] = 0x00;
    response[(*response_index)++] = 60;

    response[(*response_index)++] = 0x00;
    response[(*response_index)++] = 0x04;

    response[(*response_index)++] = 0x08;
    response[(*response_index)++] = 0x08;
    response[(*response_index)++] = 0x08;
    response[(*response_index)++] = 0x08;
  }
}

// Function to print bytes of the response array in hexadecimal format
void printResponseHex(const char *str, const unsigned char *response,
                      size_t size) {
  printf("%s %ld:\n", str, size);
  for (size_t i = 0; i < size; ++i) {
    printf("%02X ", response[i]); // Print each byte in hexadecimal format
    if ((i + 1) % 16 ==
        0) { // Newline after every 16 bytes for better readability
      printf("\n");
    }
  }
  // Print a newline if the last line didn't end with one
  if (size % 16 != 0) {
    printf("\n");
  }
}

int main(int argc, char *argv[]) {
  // Disable output buffering
  setbuf(stdout, NULL);

  // Connect to forward socket
  char *resolver = argv[2];
  char *colon_pos = strchr(resolver, ':');
  size_t ip_length = colon_pos - resolver;
  char ip[ip_length + 1];
  strncpy(ip, resolver, ip_length);
  ip[ip_length] = '\0';
  char *port_str = colon_pos + 1;
  int port = atoi(port_str);

  int udpSocket, client_addr_len;
  struct sockaddr_in clientAddress;

  udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSocket == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEPORT failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(2053),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(udpSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  size_t bytesRead;
  size_t request_index;
  size_t response_index;
  unsigned char buffer[BUFFER_SIZE];
  unsigned char response[BUFFER_SIZE];
  unsigned char answers_buffer[BUFFER_SIZE];
  size_t answers_buffer_index = 0;
  socklen_t clientAddrLen = sizeof(clientAddress);

  while (1) {
    // Receive data
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&clientAddress, &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }

    buffer[bytesRead] = '\0';
    // printf("Received %zu bytes\n", bytesRead);
    // printResponseHex("Request", buffer, bytesRead);

    // start
    // Forward the buffer to the server at 127.0.0.1:5453
    int forwardSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (forwardSocket == -1) {
      perror("Socket creation failed for forwarding");
      exit(EXIT_FAILURE);
    }

    struct sockaddr_in forward_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(5354),
    };

    if (inet_pton(AF_INET, "127.0.0.1", &forward_addr.sin_addr) <= 0) {
      perror("Invalid address for forwarding");
      close(forwardSocket);
      exit(EXIT_FAILURE);
    }
    // end

    // reset response to 0s
    memset(response, 0, sizeof(response));
    request_index = 12;
    response_index = 12;
    answers_buffer_index = 0;

    char num_questions = add_header(response, buffer);
    while (request_index < bytesRead) {
      unsigned char send_buffer[BUFFER_SIZE];
      unsigned char recv_buffer[BUFFER_SIZE];
      memset(send_buffer, 0, sizeof(send_buffer));
      memset(recv_buffer, 0, sizeof(recv_buffer));

      memcpy(send_buffer, response, 12);

      size_t old_response_index = response_index;
      add_question(response, buffer, &request_index, &response_index);
      memcpy(send_buffer + 12, response + old_response_index,
             response_index - old_response_index);

      // printResponseHex("Buffer", buffer,
      //                  12 + response_index - old_response_index);
      // printResponseHex("send_buffer", send_buffer,
      //                  12 + response_index - old_response_index);

      if (sendto(forwardSocket, send_buffer,
                 12 + response_index - old_response_index, 0,
                 (struct sockaddr *)&forward_addr,
                 sizeof(forward_addr)) == -1) {
        perror("Failed to send data to forwarding server");
        close(forwardSocket);
        exit(EXIT_FAILURE);
      }

      // printf("sent!\n");

      // Receive the response from the forwarding server
      struct sockaddr_in forwardResponseAddr;
      socklen_t forwardResponseAddrLen = sizeof(forwardResponseAddr);
      ssize_t responseSize = recvfrom(
          forwardSocket, recv_buffer, sizeof(recv_buffer), 0,
          (struct sockaddr *)&forwardResponseAddr, &forwardResponseAddrLen);
      if (responseSize == -1) {
        perror("Failed to receive data from forwarding server");
        close(forwardSocket);
        exit(EXIT_FAILURE);
      }

      recv_buffer[responseSize] = '\0';
      // printResponseHex("Received data", recv_buffer, responseSize);
      // Null-terminate the received data

      memcpy(answers_buffer + answers_buffer_index,
             recv_buffer + 12 + response_index - old_response_index,
             responseSize - (12 + response_index - old_response_index));

      answers_buffer_index +=
          responseSize - (12 + response_index - old_response_index);
    }
    close(forwardSocket);
    // add_answer(response, &response_index);
    memcpy(response + response_index, answers_buffer, answers_buffer_index);
    response_index += answers_buffer_index;
    // printResponseHex("Response", response, bytesRead);
    response[5] = num_questions;
    response[7] = num_questions;
    response[2] = buffer[2] | 0x80;
    response[3] = (buffer[2] & 0b01111000) == 0 ? 0 : 0x04;
    // printResponseHex("Full Response", response, response_index);
    // printf("----------------------------------------\n");

    // Send response
    if (sendto(udpSocket, response, sizeof(response), 0,
               (struct sockaddr *)&clientAddress,
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);

  return 0;
}
