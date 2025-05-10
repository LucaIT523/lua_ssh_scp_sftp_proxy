require "resty.openssl.ssl"
local nginx_aux = require("resty.openssl.auxiliary.nginx")

local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("strmproxy.utils.json") end
local ffi = require "ffi"
local C = ffi.C
ffi.cdef [[
    /* timeout control structure */
    typedef struct t_timeout_ {
        double block;          /* maximum time for blocking calls */
        double total;          /* total number of milliseconds for operation */
        double start;          /* time of start of operation */
    } t_timeout;
    typedef t_timeout *p_timeout;

    /* interface to error message function */
    typedef const char *(*p_error) (
        void *ctx,          /* context needed by send */
        int err             /* error code */
    );

    typedef int (*p_send) (
        void *ctx,          /* context needed by send */
        const char *data,   /* pointer to buffer with data to send */
        size_t count,       /* number of bytes to send from buffer */
        size_t *sent,       /* number of bytes sent uppon return */
        p_timeout tm        /* timeout control */
    );
            
    /* interface to recv function */
    typedef int (*p_recv) (
        void *ctx,          /* context needed by recv */
        char *data,         /* pointer to buffer where data will be written */
        size_t count,       /* number of bytes to receive into buffer */
        size_t *got,        /* number of bytes received uppon return */
        p_timeout tm        /* timeout control */
    );
    typedef int t_socket;
    typedef struct t_io_ {
        void *ctx;          /* context needed by send/recv */
        p_send send;        /* send function pointer */
        p_recv recv;        /* receive function pointer */
        p_error error;      /* strerror function */
    } t_io;
    typedef t_io *p_io;
            
    /* buffer control structure */
    typedef struct t_buffer_ {
        double birthday;        /* throttle support info: creation time, */
        size_t sent, received;  /* bytes sent, and bytes received */
        p_io io;                /* IO driver used for this buffer */
        p_timeout tm;           /* timeout management for this buffer */
        size_t first, last;     /* index of first and last bytes of stored data */
        char data[8192];        /* storage space for buffer data */
    } t_buffer;
    typedef t_buffer *p_buffer;

    typedef struct t_ssl_    {
        t_socket sock;
        t_io io;
        t_buffer buf;
        t_timeout tm;
        SSL *ssl;
        int state;
        int error;
    } t_ssl;

    typedef t_ssl* p_ssl;
    
    int SSL_get_fd(SSL *s);
    int SSL_pending(SSL *s);
    int SSL_has_pending(const SSL *s);
    SSL_SESSION *SSL_get_session(SSL *a);
    int SSL_set_session(SSL *s, SSL_SESSION *session);
    int SSL_shutdown(SSL *s);
    int SSL_do_handshake(SSL *s);
    int SSL_get_error(SSL *s, int err);
]]

local _M = {}

local function SSL_get_fd(conn)
    return C.SSL_get_fd(conn)
end

local function SSL_pending(conn)
    return C.SSL_pending(conn)
end

local function SSL_has_pending(conn)
    return C.SSL_has_pending(conn)
end

local function SSL_do_handshake(conn)
    return C.SSL_do_handshake(conn)
end

local function SSL_shutdown(conn)
    return C.SSL_shutdown(conn)
end

local function SSL_get_error(conn, err)
    return C.SSL_get_error(conn, err)
end

local function SSL_get_session(conn)
    return C.SSL_get_session(conn)
end

local function SSL_set_session(conn, session)
    return C.SSL_set_session(conn, session)
end

local function SSL_get_ctx(conn)
    local ctx = ffi.cast(ffi.typeof("p_ssl"), conn)
    return ctx[0]
end

return {
    SSL_get_ctx = SSL_get_ctx,
    SSL_get_fd = SSL_get_fd,
    SSL_pending = SSL_pending,
    SSL_has_pending = SSL_has_pending,
    SSL_do_handshake = SSL_do_handshake,
    SSL_get_session = SSL_get_session,
    SSL_set_session = SSL_set_session,
    SSL_shutdown = SSL_shutdown,
    SSL_get_error = SSL_get_error
}