#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

void add_header(unsigned char *response, unsigned char *buffer) {
  // big endian (start putting the bigger address)
  // low address          high address
  // [MSB, ....................., LSB]

  // ID 8 bits
  response[0] = buffer[0];
  // ID 8 bits
  response[1] = buffer[1];
  // QR 1 bit, OPCODE 4 bits, AA 1 bit, TC 1 bit, RD 1 bit
  response[2] = buffer[2] | 0x80;
  // RA 1 bit, Z 3 bits, RCODE 4 bits
  response[3] = (buffer[2] & 0b01111000) == 0 ? 0 : 0x04;
  // QDCOUNT 8 bits
  response[4] = buffer[4];
  // QDCOUNT 8 bits
  response[5] = buffer[5];
  // ANCOUNT 8 bits
  response[6] = buffer[6];
  // ANCOUNT 8 bits
  response[7] = buffer[5]; // Same as question count
  // NSCOUNT 8 bits
  response[8] = buffer[8];
  // NSCOUNT 8 bits
  response[9] = buffer[9];
  // ARCOUNT 8 bits
  response[10] = buffer[10];
  // ARCOUNT 8 bits
  response[11] = buffer[11];
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

int main() {
  // Disable output buffering
  setbuf(stdout, NULL);

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
  unsigned char buffer[512];
  unsigned char response[512];
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
    // printf("Received %zu bytes: %s\n", bytesRead, buffer);
    // printResponseHex("Request", buffer, bytesRead);

    // reset response to 0s
    memset(response, 0, sizeof(response));
    request_index = 12;
    response_index = 12;

    add_header(response, buffer);
    while (request_index < bytesRead) {
      add_question(response, buffer, &request_index, &response_index);
      // printf("response_index: %zu\n", response_index);
      // printf("request_index: %zu\n", request_index);
      // printResponseHex("Response", response, response_index);
      // printf("----------------------------------------\n");
    }
    add_answer(response, &response_index);
    // printResponseHex("Response", response, bytesRead);
    // printResponseHex("Response", response, response_index);
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

// stage 3 response
// 04 D2 80 00 00 01 00 00 00 00 00 00 0C 63 6F 64
// 65 63 72 61 66 74 65 72 73 02 69 6F 00 00 01 00
// 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

// stage 4 response
// 04 D2 80 00 00 01 00 01 00 00 00 00 0C 63 6F 64
// 65 63 72 61 66 74 65 72 73 02 69 6F 00 00 01 00
// 01 0C 63 6F 64 65 63 72 61 66 74 65 72 73 02 69
// 6F 00 00 01 00 01 00 00 00 3C 00 04 38 38 38 38
