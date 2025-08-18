#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ristretto255.h"

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

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<64UL ) ) return -1;

  uchar *b1 = (uchar*)data;
  uchar *b2 = (uchar*)data + 32;
  // TODO does roundtrip make sense?
  // uchar out1[32] = { 0 };
  // uchar out2[32] = { 0 };

  fd_ristretto255_point_t p1 = { 0 };
  fd_ristretto255_point_t p2 = { 0 };
  fd_ristretto255_point_t h1 = { 0 };
  fd_ristretto255_point_t h2 = { 0 };
  
  fd_ristretto255_point_t *r1 = fd_ristretto255_point_frombytes( &p1, b1 );
  fd_ristretto255_point_t *r2 = fd_ristretto255_point_frombytes( &p2, b2 );

  // Validate p1
  int p1_valid = fd_ristretto255_point_validate( b1 );
  if ( p1_valid ) {
    FD_TEST( r1 != NULL );
    FD_TEST( r1 = &p1 );
    // TODO does roundtrip make sense?
    // fd_ristretto255_point_tobytes( (uchar*)&out1, r1 );
    // FD_TEST( memcmp(out1, b1, 32) == 0 );
  } else {
    FD_TEST( r1 == NULL );
  }

  // Validate p2
  int p2_valid = fd_ristretto255_point_validate( b2 );
  if ( p2_valid ) {
    FD_TEST( r2 != NULL );
    FD_TEST( r2 = &p2 );
    // TODO does roundtrip make sense?
    // fd_ristretto255_point_tobytes( (uchar*)&out2, r2 );
    // FD_TEST( memcmp( out2, b2, 32 ) == 0 );
  } else {
    FD_TEST( r1 == NULL );
  }

  if ( !p1_valid || !p2_valid ) {
    return 0;
  }

  fd_ristretto255_point_eq( r1, r2 );
  fd_ristretto255_point_eq_neg( r1, r2 );
  
  if( FD_UNLIKELY( size<128UL ) ) return -1;

  fd_ristretto255_hash_to_curve( &h1, (uchar*)data+64 );
  fd_ristretto255_map_to_curve( &h2, (uchar*)data+64 );

  return 0;
}
