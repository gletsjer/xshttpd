/* FastCGI specification defined */

typedef struct {
	unsigned char version;
	unsigned char type;
	unsigned char request_id_1;
	unsigned char request_id_0;
	unsigned char content_length_1;
	unsigned char content_length_0;
	unsigned char padding_length;
	unsigned char reserved;
} FCGI_record;

typedef struct {
	unsigned char name_length;  /* == 0??? ????b */
	unsigned char value_length; /* == 0??? ????b */
} FCGI_name_value_pair_11;

typedef struct {
	unsigned char name_length;    /* == 0??? ????b */
	unsigned char value_length_3; /* == 1??? ????b */
	unsigned char value_length_2;
	unsigned char value_length_1;
	unsigned char value_length_0;
} FCGI_name_value_pair_14;

typedef struct {
	unsigned char name_length_3; /* == 1??? ????b */
	unsigned char name_length_2;
	unsigned char name_length_1;
	unsigned char name_length_0;
	unsigned char value_length;  /* == 0??? ????b */
} FCGI_name_value_pair_41;

typedef struct {
	unsigned char name_length_3; /* == 1??? ????b */
	unsigned char name_length_2;
	unsigned char name_length_1;
	unsigned char name_length_0;
	unsigned char value_length_3; /* == 1??? ????b */
	unsigned char value_length_2;
	unsigned char value_length_1;
	unsigned char value_length_0;
} FCGI_name_value_pair_44;

typedef struct {
	unsigned char type;
	unsigned char reserved[7];
} FCGI_unknown_type;

typedef struct {
	unsigned char role_1;
	unsigned char role_0;
	unsigned char flags;
	unsigned char reserved[5];
} FCGI_begin;

typedef struct {
	unsigned char status_3;
	unsigned char status_2;
	unsigned char status_1;
	unsigned char status_0;
	unsigned char prot_status;
	unsigned char reserved[3];
} FCGI_end;

#define FCGI_HEADER_LEN 8
#define FCGI_VERSION_1 1

#define FCGI_BEGIN_REQUEST      1
#define FCGI_ABORT_REQUEST      2
#define FCGI_END_REQUEST        3
#define FCGI_PARAMS             4
#define FCGI_STDIN              5
#define FCGI_STDOUT             6
#define FCGI_STDERR             7
#define FCGI_DATA               8
#define FCGI_GET_VALUES         9
#define FCGI_GET_VALUES_RESULT 10
#define FCGI_UNKNOWN_TYPE      11
#define FCGI_MAXTYPE           (FCGI_UNKNOWN_TYPE)

#define FCGI_NULL_REQUEST_ID    0

#define FCGI_KEEP_CONN          1

#define FCGI_RESPONDER          1
#define FCGI_AUTHORIZER         2
#define FCGI_FILTER             3

#define FCGI_REQUEST_COMPLETE   0
#define FCGI_CANT_MPX_CONN      1
#define FCGI_OVERLOADED         2
#define FCGI_UNKNOWN_ROLE       3

#define FCGI_MAX_CONNS          "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS           "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS         "FCGI_MPXS_CONNS"

#define FCGI_MAX_LENGTH					65535

/* xshttpd defined */

typedef struct {
	size_t  buffer_size;
	size_t  env_size;
	char*   buffer;
} fcgi_env;

typedef struct {
	char    type;
	char*   host;
	char*   port;
	char*   unixsocket;
	int     socket;
} fcgi_connection;

#define FCGI_PAIR_TYPE_11       0x00
#define FCGI_PAIR_TYPE_14       0x01
#define FCGI_PAIR_TYPE_41       0x02
#define FCGI_PAIR_TYPE_44       0x03

#define FCGI_PAIR_LONG_NAME     0x02
#define FCGI_PAIR_LONG_VALUE    0x01

#define FCGI_UNIX_SOCKET        0x01
#define FCGI_INET_SOCKET        0x02

/* MAX_BUFFER may NOT be more than FCGI_MAX_LENGTH */
#define FCGI_MAX_BUFFER         32768
