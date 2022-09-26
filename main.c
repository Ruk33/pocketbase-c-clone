/*
list with filters and sorting

SELECT record_id
FROM records
JOIN fields ON fields.rowid = record_field
-- sorting by field
WHERE field_name = "email"
AND record_id IN (
    -- all filters

    SELECT record_id
    FROM records
    JOIN fields ON fields.rowid = record_field 
    JOIN collections ON collections.rowid = field_collection
    WHERE collection_name = "user"
    
    INTERSECT
    
    SELECT record_id
    FROM records
    JOIN fields ON fields.rowid = record_field 
    WHERE field_name = "password"
    AND record_value = "pass"
    
    INTERSECT  
    
    SELECT record_id
    FROM records
    JOIN fields ON fields.rowid = record_field 
    WHERE field_name = "email"
    AND record_value = "fran2@email.com"
    GROUP BY record_id

)
ORDER BY record_value DESC
-- pagination
-- LIMIT 10
-- OFFSET 1

after that, we got the ids of the records sorted
run another query to fetch data.

--

possible create query with filters

SELECT 
"1234" AS "req.user.id", --> replace with values
"franco" AS "name"
WHERE "req.user.id" = "12342";

--

users

insert into collections(collection_name) values ("profile");
insert into 
fields (field_collection_id, field_name, field_type, field_req, field_uniq) 
values ((select rowid from collections where collection_name = "profile"), "name", "text", 0, 0);
insert into 
fields (field_collection_id, field_name, field_type, field_req, field_uniq) 
values ((select rowid from collections where collection_name = "profile"), "user_id", "text", 0, 0);



*/

#include <stddef.h>     // size_t
#include <unistd.h>     // close
#include <stdio.h>      // printf, snprintf
#include <string.h>     // memcpy, strncpy, strncmp
#include <assert.h>     // assert
#include <time.h>       // time_t, time
#include <sqlite3.h>
#include "include/asocket.h"
#include "include/http_request.h"
#include "include/json_read.h"

#define kb(x) \
    ((size_t) ((x) * 1024))

#define mb(x) \
    ((size_t) (kb(x) * 1024))

#define min(a, b) \
    ((a) < (b) ? (a) : (b))

#define str_matches(a, b) \
    (strncmp(a, b, sizeof(a) - 1) == 0)

#define str_cpy(dest, src) \
    (strncpy(dest, src, min(sizeof(dest), sizeof(src))) - 1)

#define arr_len(x) \
    (sizeof(x) / sizeof(*(x)))

#define for_each(type, name, arr) \
    for (type *name = (arr); name < (arr) + arr_len(arr); name++)

#define sqlite_cpy_text_ex(dest, op, col) \
    (sqlite_cpy_text(dest, op, col, sizeof(dest) - 1))

#define write_response_ex(req, code, body) \
    (write_response(req, code, body, sizeof(body) - 1))

// configurable
#define max_in_size (mb(8))
#define max_out_size (mb(8))
#define max_requests (8)

struct user {
    int id;
    char email[64];
    int is_admin;
};

struct collection {
    int id;
    char name[32];
};

struct field {
    int id;
    int collection_id;
    char name[16];
    char type[16];
    int required;
    int uniq;
};

// struct record {
//     int id;
//     int record_id;
//     int field_id;
//     char *value;
// };

struct fields_request {
    char collection_name[32];
    struct field results[16];
    size_t result_count;
};

struct request {
    int socket;
    struct user user;
    char in[max_in_size];
    char out[max_out_size];
    size_t in_size;
    size_t out_size;
    size_t out_sent_size;
};

struct sqlite_operation {
    sqlite3 *conn;
    sqlite3_stmt *stmt;
    char *query;
    int failed;
};

static struct user guest = {.id = 0, .email = "guest", .is_admin = 0};
static struct request requests[max_requests] = {0};

static void sqlite_check_err(struct sqlite_operation *op, int last_result)
{
    assert(op);
    if (op->failed)
        return;

    switch (last_result) {
    case SQLITE_OK:
    case SQLITE_ROW:
    case SQLITE_DONE:
        return;
    default:
        break;
    }

    const char *err = sqlite3_errmsg(op->conn);
    printf("sqlite error: %s\n", err ? err : "no error present :|");
    printf("query was: %s\n", op->query);
    op->failed = 1;
}

static void sqlite_open(struct sqlite_operation *op)
{
    assert(op);
    if (op->conn)
        return;
    // SQLITE_OPEN_CREATE = create if required.
    // SQLITE_OPEN_NOMUTEX = allow multiple threads to safely use the database.
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
    sqlite_check_err(op, sqlite3_open_v2("db", &op->conn, flags, 0));
}

static int sqlite_execute(struct sqlite_operation *op)
{
    assert(op);
    int result = sqlite3_step(op->stmt);
    sqlite_check_err(op, result);
    return result;
}

static void sqlite_begin_transaction(struct sqlite_operation *op)
{
    assert(op);
    if (!op->conn)
        sqlite_open(op);
    op->query = "begin transaction;";
    sqlite_check_err(op, sqlite3_exec(op->conn, op->query, 0, 0, 0));
}

static void sqlite_commit_transaction(struct sqlite_operation *op)
{
    assert(op);
    op->query = "end transaction;";
    sqlite_check_err(op, sqlite3_exec(op->conn, op->query, 0, 0, 0));
}

static void sqlite_rollback_transaction(struct sqlite_operation *op)
{
    assert(op);
    op->query = "rollback;";
    sqlite_check_err(op, sqlite3_exec(op->conn, op->query, 0, 0, 0));
}

static void sqlite_share_conn(struct sqlite_operation *dest, struct sqlite_operation *src)
{
    assert(dest);
    assert(src);
    dest->conn = src->conn;
    dest->failed = src->failed;
}

static void sqlite_begin_query(struct sqlite_operation *op, char *query)
{
    assert(op);
    if (!op->conn)
        sqlite_open(op);
    op->query = query;
    sqlite_check_err(op, sqlite3_prepare_v2(op->conn, query, -1, &op->stmt, 0));
}

static void sqlite_end_query(struct sqlite_operation *op)
{
    assert(op);
    if (op->stmt)
        sqlite_check_err(op, sqlite3_finalize(op->stmt));
    op->stmt = 0;
}

static void sqlite_close(struct sqlite_operation *op)
{
    assert(op);
    sqlite_end_query(op);
    if (op->conn)
        sqlite_check_err(op, sqlite3_close(op->conn));
    op->conn = 0;
}

static void sqlite_bind_text(struct sqlite_operation *op, char *key, char *value, int n)
{
    assert(op);
    assert(key);
    assert(value);
    int key_index = sqlite3_bind_parameter_index(op->stmt, key);
    sqlite_check_err(op, sqlite3_bind_text(op->stmt, key_index, value, n, 0));
}

static void sqlite_bind_int(struct sqlite_operation *op, char *key, int value)
{
    assert(op);
    assert(key);
    int key_index = sqlite3_bind_parameter_index(op->stmt, key);
    sqlite_check_err(op, sqlite3_bind_int(op->stmt, key_index, value));
}

static void sqlite_cpy_text(char *dest, struct sqlite_operation *op, int col, int n)
{
    assert(dest);
    assert(op);
    const char *src = (const char *) sqlite3_column_text(op->stmt, col);
    if (src)
        strncpy(dest, src, n);
}

static void sqlite_cpy_int(int *dest, struct sqlite_operation *op, int col)
{
    assert(dest);
    assert(op);
    *dest = sqlite3_column_int(op->stmt, col);
}

static int sqlite_just(char *query)
{
    assert(query);
    struct sqlite_operation op = {0};
    sqlite_begin_query(&op, query);
    sqlite_execute(&op);
    sqlite_close(&op);
    return !op.failed;
}

static void write_response(struct request *req, char *code, char *body, size_t len)
{
    assert(req);
    assert(code);
    assert(body);
    printf("len %ld.\n", len);
    int written = snprintf(
        req->out,
        sizeof(req->out) - 1,
        "HTTP/1.1 %s\r\n"
        "Server: who knows?\r\n"
        "Content-Type: text/json; charset=utf-8\r\n"
        // "Content-Length: %ld\r\n"
        "\r\n"
        "%s",
        code,
        // len,
        body
    );
    if (written == -1) {
        printf("failed to write response.\n");
        return;
    }
    req->out_size = (size_t) written;
    req->out_sent_size = 0;
}

static void append_to_response(struct request *req, char *src, int len)
{
    assert(req);
    assert(src);
    
    char *start = req->out + req->out_size;
    size_t free_space = sizeof(req->out) - req->out_size - 1;

    int written = 0;
    if (len == -1)
        written = snprintf(start, free_space, "%s", src);
    else
        written = snprintf(start, free_space, "%.*s", len, src);

    if (written == -1) {
        printf("failed to append response.\n");
        return;
    }
    req->out_size += (size_t) written;
}

static int get_uniq_id(int *dest)
{
    assert(dest);
    struct sqlite_operation op = {0};
    size_t max_tries = 10;
    *dest = 0;
    for (size_t i = 0; i < max_tries; i++) {
        *dest = (int) time(0);
        sqlite_begin_query(&op, "select 1 from records where record_id = :id limit 1;");
        sqlite_bind_int(&op, ":id", *dest);
        if (sqlite_execute(&op) == SQLITE_DONE)
            break;
        sqlite_end_query(&op);
        *dest = 0;
    }
    sqlite_close(&op);
    return *dest != 0;
}

static void get_user_by_token(struct request *req)
{
    assert(req);
    req->user = guest;

    char token[32] = {0};
    if (!json_read_str_arr(token, http_request_body(req->in), "token"))
        return;

    struct sqlite_operation op = {0};
    sqlite_begin_query(
        &op,
        "select user.rowid, user.user_email "
        "from sessions "
        "join users on users.rowid = sessions.session_user_id "
        "where session_token = :token "
        // and not expired
        "limit 1"
        ";"
    );
    sqlite_bind_text(&op, ":token", token, -1);
    if (sqlite_execute(&op) == SQLITE_ROW) {
        sqlite_cpy_int(&req->user.id, &op, 0);
        sqlite_cpy_text_ex(req->user.email, &op, 1);
    }
    sqlite_close(&op);
}

static int get_fields_from_collection(struct fields_request *dest)
{
    assert(dest);
    if (!dest->collection_name[0])
        return 0;

    struct sqlite_operation op = {0};
    sqlite_begin_query(
        &op,
        "select "
        "fields.rowid, field_collection_id, field_name, field_type, field_req, field_uniq "
        "from fields "
        "join collections on collections.rowid = fields.field_collection_id "
        "where collections.collection_name = :collection_name "
        "limit :limit"
        ";"
    );
    sqlite_bind_text(&op, ":collection_name", dest->collection_name, -1);
    sqlite_bind_int(&op, ":limit", (int) arr_len(dest->results));
    while (sqlite_execute(&op) == SQLITE_ROW) {
        struct field *field = dest->results + dest->result_count;
        sqlite_cpy_int(&field->id, &op, 0);
        sqlite_cpy_int(&field->collection_id, &op, 1);
        sqlite_cpy_text_ex(field->name, &op, 2);
        sqlite_cpy_text_ex(field->type, &op, 3);
        sqlite_cpy_int(&field->required, &op, 4);
        sqlite_cpy_int(&field->uniq, &op, 5);
        dest->result_count++;
    }
    sqlite_close(&op);
    return !op.failed;
}

static int required_fields_are_valid(struct request *req, char *params, struct fields_request *fields)
{
    assert(req);
    assert(params);
    assert(fields);
    for_each(struct field, field, fields->results) {
        if (!field->id)
            continue;
        if (!field->required)
            continue;
        if (json_read_find_value(params, field->name))
            continue;
        write_response_ex(
            req,
            "400 Bad Request",
            "{ \"error\": \"required field not found\" }"
        );
        return 0;
    }
    return 1;
}

static int uniq_fields_are_valid(struct request *req, char *params, struct fields_request *fields)
{
    assert(req);
    assert(params);
    assert(fields);
    for_each(struct field, field, fields->results) {
        if (!field->id)
            continue;
        if (!field->uniq)
            continue;
        // char *value = json_read_find_value(params, field->name);
        // check in db if field is uniq
        return 0;
    }
    return 1;
}

static int create(struct request *req, struct sqlite_operation *transaction, char *params)
{
    assert(req);
    assert(transaction);
    assert(params);

    struct fields_request fields = {0};
    if (!json_read_str_arr(fields.collection_name, params, "collection")) {
        write_response_ex(
            req,
            "400 Bad Request",
            "{ \"error\": \"collection name is required.\" }"
        );
        return 0;
    }

    if (!get_fields_from_collection(&fields)) {
        write_response_ex(
            req,
            "500 Internal Server Error",
            "{ \"error\": \"unable to get collection's fields.\" }"
        );
        return 0;
    }

    if (!required_fields_are_valid(req, params, &fields))
        return 0;

    if (!uniq_fields_are_valid(req, params, &fields))
        return 0;

    int record_id = 0;
    if (!get_uniq_id(&record_id)) {
        write_response_ex(
            req,
            "500 Internal Server Error",
            "{ \"error\": \"unable to calculate uniq record id.\" }"
        );
        return 0;
    }

    int succeed = 1;
    append_to_response(req, "{\"created\": {", -1);
    for_each(struct field, field, fields.results) {
        if (!field->id)
            break;
        struct sqlite_operation op = {0};
        sqlite_share_conn(&op, transaction);
        sqlite_begin_query(
            &op,
            "insert into records "
            "(record_id, record_field_id, record_value)"
            "values "
            "(:id, :field_id, :value)"
            ";"
        );
        sqlite_bind_int(&op, ":id", record_id);
        sqlite_bind_int(&op, ":field_id", field->id);
        char *value = json_read_find_value(params, field->name);
        // skip initial ".
        value++;
        char *end_of_value = value;
        // find end of value/string.
        while (!(*end_of_value == '"' && *(end_of_value - 1) != '\\'))
            end_of_value++;
        int value_len = (int) (end_of_value - value);
        sqlite_bind_text(&op, ":value", value, value_len);
        sqlite_execute(&op);
        sqlite_end_query(&op);
        // TODO: make sure the values are all strings.
        succeed = succeed && !op.failed;
        if (!succeed) 
            break;
        char key[32] = {0};
        snprintf(key, sizeof(key) - 1, "\"%s\": \"", field->name);
        append_to_response(req, key, -1);
        append_to_response(req, value, value_len + 1);
        append_to_response(req, ",", -1);
    }
    if (succeed) {
        // get rid of the last comma.
        req->out_size -= 1;
        append_to_response(req, "}}", -1);
        return 1;
    }

    write_response_ex(
        req,
        "500 Internal Server Error",
        "{ \"error\": \"something shit the bed.\" }"
    );
    return 0;
}

static void handle_request(struct request *req)
{
    assert(req);
    if (http_request_is_partial(req->in))
        return;

    get_user_by_token(req);

    struct sqlite_operation transaction = {0};
    sqlite_begin_transaction(&transaction);

    char *cursor = http_request_body(req->in);
    size_t max_operations = 8;

    write_response_ex(req, "200 OK", "{\"result\": [");
    for (size_t i = 0; i < max_operations; i += 1) {
        char type[8] = {0};
        cursor = json_read_str_arr(type, cursor, "type");
        if (!cursor) {
            printf("no type found. exiting out of the loop.\n");
            break;
        }

        char collection[32] = {0};
        if (!json_read_str_arr(collection, cursor, "collection")) {
            write_response_ex(
                req,
                "400 Bad Request",
                "{ \"error\": \"collection name is required.\" }"
            );
            goto rollback;
        }

        if (str_matches("create", type)) {
            // check for rules
            // internal select 1 query with filter?
            if (!create(req, &transaction, cursor))
                goto rollback;
            continue;
        }

        if (str_matches("update", type)) {
            write_response_ex(req, "501 Not Implemented", "yep, it's not here yet.");
            goto rollback;
        }

        if (str_matches("delete", type)) {
            write_response_ex(req, "501 Not Implemented", "yep, it's not here yet.");
            goto rollback;
        }

        if (str_matches("read", type)) {
            write_response_ex(req, "501 Not Implemented", "yep, it's not here yet.");
            goto rollback;
        }

        if (str_matches("list", type)) {
            write_response_ex(req, "501 Not Implemented", "yep, it's not here yet.");
            goto rollback;
        }
    }
    append_to_response(req, "]}", -1);
    sqlite_commit_transaction(&transaction);
    sqlite_close(&transaction);
    return;

rollback:
    sqlite_rollback_transaction(&transaction);
    sqlite_close(&transaction);
}

static struct request *request_assigned_to_socket(int socket)
{
    for_each(struct request, req, requests) {
        if (req->socket == socket)
            return req;
    }
    return 0;
}

static struct request *get_free_request(void)
{
    int free_socket = 0;
    struct request *req = request_assigned_to_socket(free_socket);
    if (req)
        memset(req, 0, sizeof(*req));
    return req;
}

static void socket_event_handler(int socket, enum asocket_event event, void *read, size_t len)
{
    struct request *req = 0;

    switch (event) {
    case ASOCKET_NEW_CONN:
        printf("new connection.\n");
        req = get_free_request();
        if (!req) {
            printf("unable to accept new request. all requests are occupied!\n");
            printf("the connection will be closed.\n");
            close(socket);
            return;
        }
        req->socket = socket;
        printf("connection accepted. waiting for requests.\n");
        break;
    case ASOCKET_READ:
        printf("new request\n");
        if (!read || !len) {
            printf("empty request found! will be ignored.\n");
            return;
        }
        req = request_assigned_to_socket(socket);
        if(!req) {
            printf("no socket assigned to request was found. ignoring possible read.\n");
            return;
        }
        if (sizeof(req->in) < req->in_size + len) {
            printf("request bigger than buffer.\n");
            printf("the connection will be closed.\n");
            memset(req, 0, sizeof(*req));
            close(socket);
            return;
        }
        memcpy(req->in + req->in_size, read, len);
        req->in_size += len;
        printf("chunk of request received, trying to handle it...\n");
        handle_request(req);
        break;
    case ASOCKET_CAN_WRITE:
        printf("can write. checking for pending response.\n");
        req = request_assigned_to_socket(socket);
        if (!req) {
            printf("no socket assigned to request was found. ignoring possible writing\n");
            return;
        }
        if (!req->out_size) {
            printf("no response was found, ignoring.\n");
            return;
        }
        req->out_sent_size += asocket_write(
            req->socket,
            req->out + req->out_sent_size,
            req->out_size - req->out_sent_size
        );
        printf("writing response chunk.\n");
        // reset when the entire packet has been sent.
        if (req->out_sent_size >= req->out_size) {
            printf("entire response sent! closing the connection.\n");
            memset(req, 0, sizeof(*req));
            close(socket);
        }
        break;
    case ASOCKET_CLOSED:
        printf("connection closed by client.\n");
        req = request_assigned_to_socket(socket);
        if (req)
            memset(req, 0, sizeof(*req));
        break;
    default:
        break;
    }
}

static void create_tables(void)
{
    int succeed = 1;
    succeed = succeed && sqlite_just(
        "create table if not exists collections("
        "   collection_name text"
        ");"
    );
    succeed = succeed && sqlite_just(
        "create table if not exists fields("
        "   field_collection_id int,"
        "   field_name text,"
        "   field_type text,"
        "   field_req int,"
        "   field_uniq int"
        ");"
    );
    succeed = succeed && sqlite_just(
        "create table if not exists records("
        "   record_field_id int,"
        "   record_value text,"
        "   record_id int"
        ");"
    );
    succeed = succeed && sqlite_just(
        "create table if not exists users("
        "   user_email text,"
        "   user_is_admin int"
        ");"
    );
    succeed = succeed && sqlite_just(
        "create table if not exists sessions("
        "   session_user_id int,"
        "   session_token text,"
         // strftime('%s') = unixepochtime (seconds)
         // make the default to be now, but don't use unixepoch,
         // since it may not be available depending on sqlite version.
        "   session_created_at int default (strftime('%s'))"
        ");"
    );
    if (!succeed)
        printf("failed to run migrations... you may want to see what went wrong.\n");
}

int main(int argc, char **argv)
{
    int socket = 0;
    if (argc == 2) {
        char *socket_path = argv[1];
        socket = asocket_sock(socket_path);
    } else {
        socket = asocket_port(8080);
    }

    if (socket == -1) {
        printf("failed to create socket.\n");
        return 1;
    }

    create_tables();
    printf("starting listening for requests...\n");
    asocket_listen(socket, socket_event_handler);

    return 0;
}
