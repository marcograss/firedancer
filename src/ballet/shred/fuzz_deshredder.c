#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/sanitize/fd_fuzz.h"
#include "../../util/fd_util.h"
#include "fd_shred.h"
#include "fd_deshredder.h"

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
  if (size < 4) return 0;

  uint8_t strategy = data[0];
  data++;
  size--;

  size_t part_size = size / 3;
  if ( part_size == 0 ) return 0;

  fd_shred_t const *shred1 = fd_shred_parse( data, part_size );
  fd_shred_t const *shred2 = fd_shred_parse( data + part_size, part_size );
  fd_shred_t const *shred3 = fd_shred_parse( data + 2 * part_size, size - 2 * part_size );

  if ( !shred1 || !shred2 || !shred3 ) return 0;

  fd_shred_t const *shred_list[3] = { shred1, shred2, shred3 };
  fd_deshredder_t deshred = {0};

  if ( strategy % 2 == 0 ) {
    deshred.shreds = shred_list;
    deshred.shred_cnt = 3U;
    fd_deshredder_next( &deshred );
  } else {
    for ( int i = 0; i < 3; ++i ) {
      deshred.shreds = &shred_list[i];
      deshred.shred_cnt = 1U;
      fd_deshredder_next( &deshred );
    }
  }

  return 0;
}
