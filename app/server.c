#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
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

void add_header(unsigned char *response, uint16_t packet_identifier,
                uint16_t other, uint16_t question_count,
                uint16_t answer_record_count, uint16_t authority_record_count,
                uint16_t additional_record_count) {
  size_t index = 0;
  response[index++] = (packet_identifier & 0xff00) >> 8;
  response[index++] = packet_identifier & 0xff;
  response[index++] = (other & 0xff00) >> 8;
  response[index++] = other & 0xff;
  response[index++] = (question_count & 0xff00) >> 8;
  response[index++] = question_count & 0xff;
  response[index++] = (answer_record_count & 0xff00) >> 8;
  response[index++] = answer_record_count & 0xff;
  response[index++] = (authority_record_count & 0xff00) >> 8;
  response[index++] = authority_record_count & 0xff;
  response[index++] = (additional_record_count & 0xff00) >> 8;
  response[index++] = additional_record_count & 0xff;
}

void add_question(unsigned char *response, char *name, uint16_t type,
                  uint16_t class) {
  size_t index = 12;
  encode_string(response, &index, name);

  response[index++] = (type & 0xff00) >> 8;
  response[index++] = type & 0xff;
  response[index++] = (class & 0xff00) >> 8;
  response[index++] = class & 0xff;
}

void add_answer(unsigned char *response, char *name, uint16_t type,
                uint16_t class, uint32_t ttl, uint16_t length, char *data) {
  size_t index = 33;
  encode_string(response, &index, name);

  response[index++] = (type & 0xff00) >> 8;
  response[index++] = type & 0xff;

  response[index++] = (class & 0xff00) >> 8;
  response[index++] = class & 0xff;

  response[index++] = (ttl & 0xff000000) >> 24;
  response[index++] = (ttl & 0xff0000) >> 16;
  response[index++] = (ttl & 0xff00) >> 8;
  response[index++] = ttl & 0xff;

  response[index++] = (length & 0xff00) >> 8;
  response[index++] = length & 0xff;

  memcpy(response + index, data, strlen(data));
  index += 4;
}

// Function to print bytes of the response array in hexadecimal format
void printResponseHex(const unsigned char *response, size_t size) {
  printf("Response %ld:\n", size);
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

  int bytesRead;
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
    printf("Received %d bytes: %s\n", bytesRead, buffer);

    // reset response to 0s
    memset(response, 0, sizeof(response));

    add_header(response, 1234, 0x8000, 1, 1, 0, 0);
    add_question(response, "codecrafters.io", 1, 1);
    add_answer(response, "codecrafters.io", 1, 1, 60, 4, "8888");
    // printResponseHex(response, 512);

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
