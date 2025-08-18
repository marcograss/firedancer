#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_bn254.h"
#include <math.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set(4);
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  ulong metadata_sz = sizeof(uint8_t);
  if ( data_sz < metadata_sz ) {
    return 0;
  }
  uchar choice = data[0];
  ulong content_sz = data_sz - metadata_sz;
  uchar *content = (uchar*)data + metadata_sz;

  switch ( choice ) {
    case 0: {
        uchar out[64];
        fd_bn254_g1_add_syscall( out, content, content_sz );
        break;
    }
    case 1: {
        uchar out[64];
        if ( content_sz < sizeof(uchar) ) {
            return 0;
        }
        uchar check_correct_sz = content[0];
        content += sizeof(uchar);
        content_sz -= sizeof(uchar);
        fd_bn254_g1_scalar_mul_syscall( out, content, content_sz, check_correct_sz );
        break;
    }
    case 2: {
        uchar out[32];
        fd_bn254_pairing_is_one_syscall( out, content, content_sz );
        break;
    }
    case 3: {
        uchar out[32];
        if ( content_sz < 64 ) {
            return 0;
        }
        fd_bn254_g1_compress( out, content );
        break;
    }
    case 4: {
        uchar out[64];
        if ( content_sz < 32 ) {
            return 0;
        }
        fd_bn254_g1_decompress( out, content );
        break;
    }
    case 5: {
        uchar out[64];
        if ( content_sz < 128 ) {
            return 0;
        }
        fd_bn254_g2_compress( out, content );
        break;
    }
    case 6: {
        uchar out[128];
        if ( content_sz < 64 ) {
            return 0;
        }
        fd_bn254_g2_decompress( out, content );
        break;
    }
  }
  return 0;
}
