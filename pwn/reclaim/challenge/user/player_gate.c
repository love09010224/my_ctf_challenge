#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "reclaim_v4_uapi.h"

#define VAULT_PATH "/root/quarantine/000"
#define FLAG_LIMIT 512U

static void fail(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static int decode_hex(const char *text, unsigned char *output, size_t size)
{
	size_t i;

	if (strlen(text) != size * 2)
		return 0;
	for (i = 0; i < size; i++) {
		unsigned int value;

		if (sscanf(text + i * 2, "%2x", &value) != 1)
			return 0;
		output[i] = (unsigned char)value;
	}
	return 1;
}

static int valid_object_name(const char *name)
{
	size_t i;

	if (strlen(name) != 32)
		return 0;
	for (i = 0; i < 32; i++)
		if (!((name[i] >= '0' && name[i] <= '9') ||
		      (name[i] >= 'a' && name[i] <= 'f')))
			return 0;
	return 1;
}

static int flag_line(const unsigned char *data, size_t length)
{
	size_t end = length;

	while (end && (data[end - 1] == '\n' || data[end - 1] == '\r'))
		end--;
	if (end < 6 || memcmp(data, "SHA{", 4) || data[end - 1] != '}')
		return 0;
	for (size_t i = 0; i < end; i++)
		if (data[i] < 0x20 || data[i] > 0x7e)
			return 0;
	return 1;
}

static void emit_vault_flag(void)
{
	unsigned char selected[FLAG_LIMIT + 1];
	size_t selected_size = 0;
	struct dirent *entry;
	DIR *directory;
	int directory_fd;

	directory_fd = open(VAULT_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (directory_fd < 0)
		fail("open box 000");
	directory = fdopendir(directory_fd);
	if (!directory)
		fail("open box 000 stream");
	while ((entry = readdir(directory)) != NULL) {
		unsigned char data[FLAG_LIMIT + 1];
		struct stat status;
		ssize_t amount;
		int fd;

		if (!valid_object_name(entry->d_name))
			continue;
		fd = openat(directory_fd, entry->d_name,
			    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0)
			continue;
		if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
		    status.st_size <= 0 || status.st_size > FLAG_LIMIT) {
			close(fd);
			continue;
		}
		memset(data, 0, sizeof(data));
		amount = read(fd, data, (size_t)status.st_size);
		close(fd);
		if (amount != status.st_size ||
		    !flag_line(data, (size_t)amount))
			continue;
		if (selected_size) {
			closedir(directory);
			fputs("ambiguous box contents\n", stderr);
			exit(EXIT_FAILURE);
		}
		memcpy(selected, data, (size_t)amount);
		selected_size = (size_t)amount;
	}
	closedir(directory);
	if (!selected_size) {
		fputs("no approval object found\n", stderr);
		exit(EXIT_FAILURE);
	}
	if (write(STDOUT_FILENO, selected, selected_size) !=
	    (ssize_t)selected_size)
		fail("write approval object");
	if (selected[selected_size - 1] != '\n' &&
	    write(STDOUT_FILENO, "\n", 1) != 1)
		fail("write approval newline");
	OPENSSL_cleanse(selected, sizeof(selected));
}

int main(void)
{
	unsigned char secret[32], nonce[32], supplied[32];
	unsigned char expected[EVP_MAX_MD_SIZE];
	unsigned int expected_size = 0;
	char response[96];
	uid_t caller_uid = getuid();
	gid_t caller_gid = getgid();
	ssize_t length;
	int fd;

	setbuf(stdout, NULL);
	(void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (geteuid() != 0) {
		fputs("approval gate is unavailable\n", stderr);
		return EXIT_FAILURE;
	}
	fd = open(RECLAIM_EVIDENCE_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fail("open approval evidence");
	length = read(fd, secret, sizeof(secret));
	close(fd);
	if (length != (ssize_t)sizeof(secret))
		fail("read approval evidence");
	if (setresgid(caller_gid, caller_gid, 0) != 0)
		fail("drop approval gid");
	if (setresuid(caller_uid, caller_uid, 0) != 0)
		fail("drop approval uid");
	if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce))
		fail("get approval nonce");
	printf("Nonce:");
	for (size_t i = 0; i < sizeof(nonce); i++)
		printf("%02x", nonce[i]);
	printf("\nMAC:");
	if (!fgets(response, sizeof(response), stdin))
		fail("read approval response");
	response[strcspn(response, "\r\n")] = '\0';
	if (!decode_hex(response, supplied, sizeof(supplied))) {
		fputs("approval rejected\n", stderr);
		goto reject;
	}
	if (!HMAC(EVP_sha256(), secret, sizeof(secret), nonce, sizeof(nonce),
		  expected, &expected_size) || expected_size != sizeof(supplied) ||
	    CRYPTO_memcmp(expected, supplied, sizeof(supplied))) {
		fputs("approval rejected\n", stderr);
		goto reject;
	}
	OPENSSL_cleanse(secret, sizeof(secret));
	OPENSSL_cleanse(supplied, sizeof(supplied));
	OPENSSL_cleanse(expected, sizeof(expected));
	if (setresgid(0, 0, 0) != 0)
		fail("restore approval gid");
	if (setresuid(0, 0, 0) != 0)
		fail("restore approval uid");
	emit_vault_flag();
	return EXIT_SUCCESS;

reject:
	OPENSSL_cleanse(secret, sizeof(secret));
	OPENSSL_cleanse(supplied, sizeof(supplied));
	OPENSSL_cleanse(expected, sizeof(expected));
	return EXIT_FAILURE;
}
