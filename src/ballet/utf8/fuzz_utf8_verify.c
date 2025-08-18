#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../util/sanitize/fd_fuzz.h"
#include "../../util/fd_util.h"
#include "fd_utf8.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
  fd_utf8_verify( (const char*)data, size );
  return 0;
}
