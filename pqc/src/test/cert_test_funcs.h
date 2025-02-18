
#ifndef CERT_TEST_FUNCS_H
#define CERT_TEST_FUNCS_H

#include "cert_test_params.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>  // For directory processing

// Create a new directory
#ifdef _WIN32
    #include <direct.h>  // _mkdir() for Windows
    #define MKDIR(path) _mkdir(path)
#else
    #include <unistd.h>  // access()
    #define MKDIR(path) mkdir(path, 0755)
#endif
void make_directory(const char *);

// Remove a directory
#ifdef _WIN32
    #include <direct.h>
    #define REMOVE(path) _unlink(path)
    #define RMDIR(path) _rmdir(path)
#else
    #include <unistd.h>
    #define REMOVE(path) remove(path)
    #define RMDIR(path) rmdir(path)
#endif
void delete_files_in_directory(const char *);

EVP_PKEY *generate_certificate_key(char *);
X509_REQ *generate_csr(char *, EVP_PKEY *);
X509 *generate_cert(EVP_PKEY *, X509_REQ *);
void save_to_file(char *, EVP_PKEY *, X509_REQ *, X509 *);

#endif