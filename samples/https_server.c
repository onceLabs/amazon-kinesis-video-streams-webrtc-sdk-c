#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "Samples.h"


#define SUCCESS          0
#define FAILURE          -1

#define USERNAME         "admin"
#define PASSWORD         "123456"

#define CERT_FILE        "server.crt"      // Server certificate
#define KEY_FILE         "server.key"      // Server private key

#define PORT             443               // Default https port
#define BACK_LOG         10

#define BUFFER_SIZE      4096
#define METHOD_LEN       10
#define PATH_LEN         50
#define MESSAGE_LEN      128

#define PROVISIONING_STATUS_PATH        "/provisioning/status"
#define PROVISIONING_PAIR_PATH          "/provisioning/pair"

#define AUTHORIZED_HEADER               "Authorization: Basic "
#define CONTENT_LENGTH_HEADER           "Content-Length: "

#define PROVISIONING_STATUS_RESPONSE    "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 10\n\n{status:%d}"
#define BAD_REQUEST_TEMPLATE            "HTTP/1.1 400 Bad Request\nContent-Length: 0\n\n"
#define UNAUTHORIZED_REQUEST_TEMPLATE   "HTTP/1.1 401 Unauthorized\nContent-Length: 0\n\n"
#define SERVER_INTERNAL_ERROR_TEMPLATE  "HTTP/1.1 500 Internal Server Error\nContent-Length: 0\n\n"

#define UDP_IP           "239.255.255.250"
#define UDP_PORT         3702
#define UUID_LEN         1024

#define UUID_PARSE                      "uuid:"
#define UDP_RECV_XML_HEADER             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsdd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:chan=\"http://schemas.microsoft.com/ws/2005/02/duplex\" xmlns:wsa5=\"http://www.w3.org/2005/08/addressing\" xmlns:xmime=\"http://tempuri.org/xmime.xsd\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:wsrfbf=\"http://docs.oasis-open.org/wsrf/bf-2\" xmlns:wstop=\"http://docs.oasis-open.org/wsn/t-1\" xmlns:wsrfr=\"http://docs.oasis-open.org/wsrf/r-2\" xmlns:tdn=\"http://www.onvif.org/ver10/network/wsdl\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">\n\
<SOAP-ENV:Header>\n\
<wsa:MessageID>uuid:2419d68a-2dd2-21b2-a205-4A69A95DB56D</wsa:MessageID>\n\
<wsa:RelatesTo>uuid:"
#define UDP_RECV_XML_END                "</wsa:RelatesTo>\n\
<wsa:To SOAP-ENV:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>\n\
<wsa:Action SOAP-ENV:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>\n\
</SOAP-ENV:Header>\n\
<SOAP-ENV:Body>\n\
<wsdd:ProbeMatches>\n\
<wsdd:ProbeMatch>\n\
<wsa:EndpointReference>\n\
<wsa:Address>urn:uuid:2419d68a-2dd2-21b2-a205-4A69A95DB56D</wsa:Address>\n\
<wsa:ReferenceProperties />\n\
<wsa:ReferenceParameters />\n\
<wsa:PortType>ttl</wsa:PortType>\n\
</wsa:EndpointReference>\n\
<wsdd:Types>tds:Device</wsdd:Types>\n\
<wsdd:Scopes>onvif://www.onvif.org/type/NetworkVideoTransmitter\r\nonvif://www.onvif.org/name/IPC_2802222\r\nonvif://www.onvif.org/location/Country/China</wsdd:Scopes>\n\
<wsdd:XAddrs>http://10.0.78.15:5000/onvif/device_service</wsdd:XAddrs>\n\
<wsdd:MetadataVersion>1</wsdd:MetadataVersion>\n\
</wsdd:ProbeMatch>\n\
</wsdd:ProbeMatches>\n\
</SOAP-ENV:Body>\n\
</SOAP-ENV:Envelope>\n\n"

#define IOT_CERTIFICATE_PATH     "./iot_certificate.pem.crt"
#define IOT_PRIVATE_KEY_PATH     "./iot_private.pem.key"
#define IOT_ROOT_CA_PATH         "./iot_root_ca.pem.crt"
#define IOT_CONFIG_PATH          "./iot_config.json"


static void str_replace( char * cp, int n, char * str )
{
    int lenofstr;
    char * tmp;
    lenofstr = strlen( str );

    if ( lenofstr < n )
    {
        tmp = cp + n;
        while ( * tmp )
        {
            *( tmp - ( n - lenofstr ) ) = *tmp;
            tmp++;
        }
        *( tmp - ( n - lenofstr ) ) = *tmp;
    }
    else if ( lenofstr > n )
    {
        tmp = cp;
        while ( * tmp ) tmp++;
        while ( tmp >= cp + n )
        {
            *( tmp + ( lenofstr - n ) ) = *tmp;
            tmp--;
        }
    }
    strncpy( cp, str, lenofstr );
}

static int save_to_file( const char * path, const char * buffer, int bufferLen )
{
    FILE * file = NULL;
    char * tmpBuffer = NULL;
    char * p = NULL;

    tmpBuffer = malloc( bufferLen + 1 );
    if ( NULL == tmpBuffer )
    {
        printf( "Malloc tmpBuffer failed.\n" );
        free( tmpBuffer );
        return FAILURE;
    }
    memset( tmpBuffer, 0, bufferLen + 1 );
    memcpy( tmpBuffer, buffer, bufferLen );

    p = strstr( tmpBuffer, "\\n" );
    while ( p )
    {
        str_replace( p, strlen("\\n"), "\n" );
        p = p + strlen( "\n" );
        p = strstr( p, "\\n" );
    }

    file = fopen( path, "w" );
    if ( file == NULL )
    {
        printf( "Open file %s failed.\n", path );
        return FAILURE;
    }

    size_t bytesWritten = fwrite( tmpBuffer, sizeof(char), bufferLen, file );

    if ( bytesWritten != bufferLen )
    {
        printf( "fwrite file %s failed.\n", path );
        fclose( file );
        return FAILURE;
    }
    
    fclose( file );
    return SUCCESS;
}

static int parse_request_header( const char * header )
{
    char * line = strtok( ( char * ) header, "\r\n" );

    while ( line != NULL )
    {
        // printf( "line: %s\n", line );
        char* authorization = strstr( line, AUTHORIZED_HEADER );
        if ( authorization != NULL )
        {
            authorization += strlen( AUTHORIZED_HEADER );
            CHAR message[ MESSAGE_LEN ] = { 0 };
            snprintf( message, MESSAGE_LEN, "%s:%s", USERNAME, PASSWORD );
            UINT32 size = strlen( message );
            CHAR  encodeMessage[ MESSAGE_LEN ] = { 0 };
            UINT32 encodeSize = sizeof( encodeMessage );
            base64Encode( message, size, ( PCHAR ) &encodeMessage, &encodeSize );
            if ( 0 == strncmp( authorization, encodeMessage, encodeSize ) )
            {
                printf( "Authorization success.\n" );
                return SUCCESS;
            }
        }
        line = strtok( NULL, "\r\n" );
    }
    fprintf( stderr, "Error authorization.\n" );
    ERR_print_errors_fp( stderr );
    return FAILURE;
}

static void handle_post_request( SSL * ssl, const char * header, const char * body )
{
    jsmn_parser parser;
    jsmntok_t tokens[ MAX_JSON_TOKEN_COUNT ];
    int tokenCount;

    FILE * file = NULL;
    int save_config = 0;
    char response[ BUFFER_SIZE ] = { 0 };
    int ret = SUCCESS;

    file = fopen( IOT_CONFIG_PATH, "w" );
    if ( file == NULL )
    {
        SSL_write( ssl, SERVER_INTERNAL_ERROR_TEMPLATE, strlen( SERVER_INTERNAL_ERROR_TEMPLATE ) );
        return;
    }

    fwrite( "{\n\t", sizeof(char), strlen("{\n\t"), file );

    // Parse the response
    jsmn_init( &parser );
    tokenCount = jsmn_parse( &parser, body, strlen(body), tokens, SIZEOF(tokens) / SIZEOF(jsmntok_t) );
    if ( ( tokenCount > 1 ) && ( tokens[0].type == JSMN_OBJECT ) )
    {
        for ( int i = 1; i < tokenCount; i++ )
        {
            save_config = 0;
            if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "ThingName") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "StreamName") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "Region") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTCertificate") )
            {
                ret |= save_to_file( IOT_CERTIFICATE_PATH, body + tokens[i+1].start, tokens[i+1].end - tokens[i+1].start );
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTPrivateKey") )
            {
                ret |= save_to_file( IOT_PRIVATE_KEY_PATH, body + tokens[i+1].start, tokens[i+1].end - tokens[i+1].start );
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTCACert") )
            {
                ret |= save_to_file( IOT_ROOT_CA_PATH, body + tokens[i+1].start, tokens[i+1].end - tokens[i+1].start );
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTEndpointUrl") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTCredentialUrl") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTCredentialEndpoint") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "IoTCredentialRoleAlias") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }
            else if ( compareJsonString( ( char * ) body, &tokens[i], JSMN_STRING, (PCHAR) "KMSKeyId") )
            {
                fwrite( body + tokens[i].start - 1, sizeof(char), tokens[i+1].end - tokens[i].start + 2, file );
                save_config = 1;
                i++;
            }

            if ( save_config )
            {
                if ( i == tokenCount-1 )
                {
                    fwrite( "\n", sizeof(char), strlen("\n"), file );
                }
                else
                {
                    fwrite( ",\n\t", sizeof(char), strlen(",\n\t"), file );
                }
            }
        }
    }
    fwrite( "}\n", sizeof(char), strlen("}\n"), file );
    fclose( file );

    if ( ret != SUCCESS )
    {
        SSL_write( ssl, SERVER_INTERNAL_ERROR_TEMPLATE, strlen( SERVER_INTERNAL_ERROR_TEMPLATE ) );
    }
    else
    {
        snprintf( response, BUFFER_SIZE, PROVISIONING_STATUS_RESPONSE, 1 );
        SSL_write( ssl, response, strlen( response ) );
    }
}

static void handle_get_request( SSL * ssl, const char * header, const char * body )
{
    char response[ BUFFER_SIZE ] = { 0 };
    int status = 0;

    FILE* file = NULL;
    file = fopen( IOT_CONFIG_PATH, "r" );
    if ( file != NULL )
    {
        fseek( file, 0, SEEK_END );
        long fileSize = ftell( file );
        fclose( file );
        if ( fileSize > 0 )
        {
            status = 1;
        }
    }

    snprintf( response, BUFFER_SIZE, PROVISIONING_STATUS_RESPONSE, status );
    SSL_write( ssl, response, strlen( response ) );
}

static void handle_client_request( SSL * ssl )
{
    char buffer[ BUFFER_SIZE ] = { 0 };
    char method[ METHOD_LEN ] = { 0 };
    char path[ PATH_LEN ] = { 0 };

    char * request_header = NULL;
    char * request_json = NULL;

    int bytes_read = 0;
    int parse_header_done = 0;
    int contentLength = -1;
    int header_bytes = 0;
    int body_bytes = 0;

    // Get Header and Body
    while ( ( bytes_read = SSL_read( ssl, buffer, sizeof( buffer ) - 1 ) ) > 0 )
    {
        buffer[ bytes_read ] = '\0';
        // printf( "Received:\n%s\n", buffer );
        if ( parse_header_done == 0 )
        {
            char * contentLengthHeader = strstr( buffer, CONTENT_LENGTH_HEADER );
            if ( contentLengthHeader )
            {
                contentLengthHeader += strlen( CONTENT_LENGTH_HEADER );
                char * endPtr = NULL;
                contentLength = strtol( contentLengthHeader, &endPtr, 10 );

                if ( endPtr == contentLengthHeader )
                {
                    printf( "Failed to parse Content-Length\n" );
                    continue;
                }
                parse_header_done = 1;
                printf( "Save header and body\n" );
                //Save header
                header_bytes = bytes_read - strlen( endPtr );
                request_header = malloc( sizeof( char ) * (header_bytes + 1) );
                memset( request_header, 0, (header_bytes + 1) );
                memcpy( request_header, buffer, header_bytes );

                //Save response json
                char * bodyPtr = endPtr + strlen("\r\n\r\n");
                body_bytes = strlen( bodyPtr );
                request_json = malloc( sizeof( char ) * (body_bytes + 1) );
                memset( request_json, 0, (body_bytes + 1) );
                memcpy( request_json, bodyPtr, body_bytes );
            }
            else
            {
                if ( bytes_read < BUFFER_SIZE )
                {
                    parse_header_done = 1;
                    printf( "Save header, no body\n" );
                    //Save header
                    header_bytes = bytes_read;
                    request_header = malloc( sizeof( char ) * (header_bytes + 1) );
                    memset( request_header, 0, (header_bytes + 1) );
                    memcpy( request_header, buffer, header_bytes );
                    break;
                }
            }
        }
        else
        {
            //Save response json
            int old_bytes_total = body_bytes;
            body_bytes += bytes_read;
            request_json = realloc( request_json, sizeof( char ) * (body_bytes + 1) );
            memcpy( request_json + old_bytes_total, buffer, bytes_read );
        }
        if ( contentLength != -1 && body_bytes < contentLength )
        {
            continue;
        }
        else if ( contentLength != -1 && body_bytes == contentLength )
        {
            request_json[ body_bytes ] = '\0';
            break;
        }
    }
    printf( "request header:\n%s\n", request_header );
    printf( "request json:\n%s\n", request_json );

    // Parse header
    if ( SUCCESS != parse_request_header( request_header ) )
    {
        SSL_write( ssl, UNAUTHORIZED_REQUEST_TEMPLATE, strlen( UNAUTHORIZED_REQUEST_TEMPLATE ) );
        return;
    }

    // Parse request, get method and path
    sscanf( request_header, "%s %s", method, path );

    if ( strcmp( method, "GET" ) == 0 && strcmp( path, PROVISIONING_STATUS_PATH ) == 0 )
    {
        handle_get_request( ssl, request_header, request_json );
    }
    else if ( strcmp( method, "POST" ) == 0 && strcmp( path, PROVISIONING_PAIR_PATH ) == 0 )
    {
        handle_post_request( ssl, request_header, request_json );
    }
    else
    {
        SSL_write( ssl, BAD_REQUEST_TEMPLATE, strlen( BAD_REQUEST_TEMPLATE ) );
    }

    // Close SSL Connection
    SSL_shutdown( ssl );
    SSL_free( ssl );

    // Free header and json
    if ( NULL != request_header )
    {
        free( request_header );
        request_header = NULL;
    }
    if ( NULL != request_json )
    {
        free( request_json );
        request_json = NULL;
    }
}

static void * OnvifBeDiscovered( void * arg )
{
    char uu_buf[ UUID_LEN ] = { 0 };
    char * cust_uuid = 0;

    struct sockaddr_in groupcast_addr, the_member;
    int sockfd;
    unsigned char loop;
    char recvmsg[ BUFFER_SIZE ] = { 0 };
    unsigned int socklen, n;
    struct ip_mreq mreq;

    // Create UDP socket
    sockfd = socket( AF_INET, SOCK_DGRAM, 0 );
    if ( sockfd < 0 )
    {
        perror( "socket creating err in udptalk" );
        pthread_exit( NULL );
    }

    memset( &mreq, 0, sizeof (struct ip_mreq) );
    inet_pton( AF_INET, UDP_IP, &the_member.sin_addr );
    bcopy( &the_member.sin_addr.s_addr, &mreq.imr_multiaddr.s_addr, sizeof( struct in_addr ) );
    // Set the address information of the source host for sending multicast messages
    mreq.imr_interface.s_addr = htonl( INADDR_ANY );
    // Joining a multicast address means adding the local machine to the multicast group,
    // where the network interface of the local machine becomes a member of the multicast group.
    // Only by joining the group can the local machine receive multicast messages.
    if ( setsockopt( sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP , &mreq, sizeof( struct ip_mreq ) ) == -1 )
    {
        perror( "Error setsockopt IP_ADD_MEMBERSHIP" );
        pthread_exit( NULL );
    }
	loop = 0;
    if ( setsockopt( sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof( loop ) ) == -1 )
    {
        perror( "Error setsockopt IP_MULTICAST_LOOP" );
        pthread_exit( NULL );
    }

    socklen = sizeof( struct sockaddr_in );
    memset( &groupcast_addr, 0, socklen );
    groupcast_addr.sin_family = AF_INET;
    groupcast_addr.sin_port = htons( UDP_PORT );
    inet_pton( AF_INET, UDP_IP, &groupcast_addr.sin_addr );
    
    // Bind
    if ( bind( sockfd, ( struct sockaddr * ) &groupcast_addr, sizeof( struct sockaddr_in ) ) == -1 )
    {
        perror( "Error binding" );
        pthread_exit( NULL );
    }

    while ( 1 )
    {
        memset( recvmsg, 0, BUFFER_SIZE );
        n = recvfrom( sockfd, recvmsg, BUFFER_SIZE - 1, 0, ( struct sockaddr * ) &the_member, &socklen );
        if ( n < 0 )
        {
            perror( "recvfrom err in udptalk!" );
            pthread_exit( NULL );
        }
        else
        {
            recvmsg[ n ] = 0;
            printf( "recv: %s\n\n", recvmsg );
            printf( "ip: %s\n", inet_ntoa( the_member.sin_addr ) );
            printf( "port: %d\n", ntohs( the_member.sin_port ) );
        }

        // Parse uuid
        cust_uuid = strstr( recvmsg, UUID_PARSE );
        if ( cust_uuid == 0 )
        {
            printf( "uuid: err!\n" );
            pthread_exit( NULL );
        }
        cust_uuid += strlen( UUID_PARSE );
        strncpy( uu_buf, cust_uuid, 36 );
        printf( "uuid: %s\n", uu_buf );

        memset( recvmsg, 0, sizeof( recvmsg ) );
        strcpy( recvmsg, UDP_RECV_XML_HEADER );
        strcat( recvmsg, uu_buf );
        strcat( recvmsg, UDP_RECV_XML_END );
        if ( sendto( sockfd, recvmsg, strlen( recvmsg ), 0, ( struct sockaddr * ) &the_member, sizeof( the_member ) ) < 0 )
        {
            printf( "sendto error!\n" );
            pthread_exit( NULL );
        }
        printf( "send ok\n" );
    }
    pthread_exit( NULL );
}

static void * OnvifHttpServices( void * arg )
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_size;
    SSL_CTX * ctx;
    SSL * ssl;

    // OpenSSL init
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL_CTX
    ctx = SSL_CTX_new( SSLv23_server_method() );
    if ( !ctx )
    {
        fprintf( stderr, "Error creating SSL context.\n" );
        ERR_print_errors_fp( stderr );
        pthread_exit( NULL );
    }

    // Load server certificate and private key
    if ( SSL_CTX_use_certificate_file( ctx, CERT_FILE, SSL_FILETYPE_PEM ) <= 0 )
    {
        fprintf( stderr, "Error loading certificate file.\n" );
        ERR_print_errors_fp( stderr );
        pthread_exit( NULL );
    }
    if ( SSL_CTX_use_PrivateKey_file( ctx, KEY_FILE, SSL_FILETYPE_PEM ) <= 0 )
    {
        fprintf( stderr, "Error loading private key file.\n" );
        ERR_print_errors_fp( stderr );
        pthread_exit( NULL );
    }

    // Create socket
    server_socket = socket( AF_INET, SOCK_STREAM, 0 );
    if ( server_socket == -1 )
    {
        perror( "Error creating socket" );
        pthread_exit( NULL );
    }

    // Set socket REUSEADDR
    int opt = 1;
    if ( setsockopt( server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof( opt ) ) )
    {
        perror( "Error setsockopt failed" );
        pthread_exit( NULL );
    }

    // Config server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    // Bind socket with server address
    if ( bind( server_socket, ( struct sockaddr * ) &server_addr, sizeof( server_addr ) ) == -1 )
    {
        perror( "Error binding socket" );
        close( server_socket );
        pthread_exit( NULL );
    }

    // Listen socket
    if ( listen( server_socket, BACK_LOG ) == -1 )
    {
        perror( "Error listening on socket" );
        close( server_socket );
        pthread_exit( NULL );
    }

    printf( "Server is running. Waiting for connections...\n" );

    while ( 1 )
    {
        // Accept client connection
        sin_size = sizeof( client_addr );
        client_socket = accept( server_socket, ( struct sockaddr * ) &client_addr, &sin_size );
        if ( client_socket == -1 )
        {
            perror( "Error accepting connection" );
            continue;
        }

        // // Set the timeout
        // struct timeval timeout;
        // timeout.tv_sec = 5;  // 5 seconds
        // timeout.tv_usec = 0;

        // // Set the socket option for receive timeout
        // if( setsockopt( client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout) ) == -1 )
        // {
        //     perror( "Error setsockopt" );
        //     close( client_socket );
        //     continue;
        // }

        // Create SSL Connection
        ssl = SSL_new( ctx );
        SSL_set_fd( ssl, client_socket );

        // SSL handshark
        if ( SSL_accept( ssl ) <= 0 )
        {
            ERR_print_errors_fp( stderr );
        }
        else
        {
            // Handle client request
            handle_client_request( ssl );
        }

        close( client_socket );
    }

    // Free sources
    close( server_socket );
    SSL_CTX_free( ctx );

    pthread_exit( NULL );
}

int main( int argc, char *argv[] )
{
    pthread_t discover = 0;
    pthread_t httpservice = 0;

    ( void ) argc;
    ( void ) argv;

    pthread_create( &discover, NULL, OnvifBeDiscovered, NULL );
    pthread_create( &httpservice, NULL, OnvifHttpServices, NULL );

    pthread_join( discover, 0 );
    pthread_join( httpservice, 0 );

    return 0;
}
