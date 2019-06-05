/****************************************************/
/************* datetime Example Server **************/
/****************************************************/
#include "datetime.h"
#include <time.h>

int
main( int argc , char * * argv )
{
	int listenfd , connfd, idx;
	struct sockaddr_in servaddr;
	char buff[ MAXLINE ];
	time_t ticks;
	pid_t pid;
	char recvline[ MAXLINE + 1];

	listenfd = socket( AF_INET , SOCK_STREAM , 0 );

	memset( &servaddr , 0 , sizeof( servaddr ) );
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl( INADDR_ANY );
	servaddr.sin_port = htons( 13 );

	bind( listenfd , (struct sockaddr *)&servaddr , sizeof( servaddr ) );
	listen( listenfd , 1024 );

	for( ; ; )
	{
		connfd = accept( listenfd , (struct sockaddr *)NULL , NULL );
        printf("Initializeing new connection...\n");
        
        if((pid = fork()) == 0)
        {
            close(listenfd);
            
            ticks = time( NULL );
            snprintf( buff , sizeof( buff ) , "服务端子进程id%d\n时间：%.24s\r\n" , getpid() , ctime( &ticks ) );
            printf("%s" , buff);
            write( connfd , buff , strlen( buff ) );
            
            if( ( idx = read( connfd , recvline , MAXLINE ) ) > 0 )  {
                recvline[ idx ] = 0;
                if( fputs( recvline , stdout ) == EOF ) {
                    printf( "fputs error\n" );
                    exit( 1 );
                }   
            }
            
            close( connfd );
            exit(0);
        }
        
		close( connfd );
	} 
}
