
#include "tls_engine.h"
#include "utils.h"


static mbedtls_x509_crt* cacert = NULL;
static mbedtls_x509_crt _cacert; // Cached certs


int tls_engine_init(tls_engine *tls)
{
    int ret;
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init( &tls->ctx );
    mbedtls_ssl_init( &tls->ssl );
    mbedtls_ssl_config_init( &tls->conf );
    mbedtls_ctr_drbg_init( &tls->ctr_drbg );
    const char *pers = "chat";

	Q_DEBUG_MSG("\n  . Seeding the random number generator..." );

    mbedtls_entropy_init( &tls->entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &tls->ctr_drbg,
                                       mbedtls_entropy_func,
                                       &tls->entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ERR_TLS_ERROR;
    }

	Q_DEBUG_MSG(" ok" );

	if(!cacert)
	{
		/*
		* 1. Initialize certificates
		*/
		mbedtls_x509_crt_init(&_cacert);
		Q_DEBUG_MSG("  . Loading the CA root certificate ...");

		ret = mbedtls_x509_crt_parse_file(&_cacert, "truststore.txt");
		if (ret < 0)
		{
			mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
			return ERR_TLS_ERROR;
		}
		Q_DEBUG_MSG(" ok (%d skipped)", ret);
		cacert = &_cacert;
	}
	// Reuse the global cacert
	tls->cacert = cacert;


    return ERR_TLS_OK;
}


void tls_engine_stop(tls_engine *tls)
{
    mbedtls_net_free( &tls->ctx );
    mbedtls_ssl_free( &tls->ssl );
    mbedtls_ssl_config_free( &tls->conf );
    mbedtls_ctr_drbg_free( &tls->ctr_drbg );
    mbedtls_entropy_free( &tls->entropy );
}

