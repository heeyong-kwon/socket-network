#ifndef PQ_SERVER_FUNCS_H
#define PQ_SERVER_FUNCS_H

#include "pq_server_params.h"


#if (DATA_TYPE == TYPE_INTEGER)
    typedef long        data_t;
    #define STR_TO_NUM  strtol
    #define NUM_MAX     INT_MAX
    #define NUM_MIN     INT_MIN
#elif (DATA_TYPE == TYPE_FLOAT)
    typedef float       data_t;
    #define STR_TO_NUM  strtof
    #define NUM_MAX     FLT_MAX
    #define NUM_MIN     -FLT_MAX
#elif (DATA_TYPE == TYPE_DOUBLE)
    typedef double      data_t;
    #define STR_TO_NUM  strtod
    #define NUM_MAX     DBL_MAX
    #define NUM_MIN     -DBL_MAX
#else
    #error "DATATYPE must be INTEGER, FLOAT, or DOUBLE"
#endif


SSL_CTX* create_server_context();
// void *handle_client(SSL *);
void handle_client_message(data_t *);
void *handle_client(void *);
int is_valid_number(const char *);
int safe_strton(const char *, data_t *);
#endif