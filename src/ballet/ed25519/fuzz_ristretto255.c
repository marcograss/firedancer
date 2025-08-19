#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  fd_log_level_stderr_set(4);
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}


int
LLVMFuzzerTestOneInput( uchar const * data, ulong size ) {
  if( FD_UNLIKELY( size<64UL ) ) return 0;

  uchar const * b1 = data;
  uchar const * b2 = data + 32;

  uchar out1[32] = { 0 };
  uchar out2[32] = { 0 };

  fd_ristretto255_point_t p1 = { 0 }, p2 = { 0 }, h1 = { 0 }, h2 = { 0 };

  fd_ristretto255_point_t *r1 = fd_ristretto255_point_frombytes( &p1, b1 );
  fd_ristretto255_point_t *r2 = fd_ristretto255_point_frombytes( &p2, b2 );

  int p1_valid = fd_ristretto255_point_validate( b1 );
  FD_TEST( (r1 != NULL) == p1_valid );
  if( p1_valid ) {
    FD_TEST( r1 == &p1 );

    // must be equal to the original point
    fd_ristretto255_point_tobytes( out1, r1 );
    FD_TEST( fd_ristretto255_point_validate( out1 ) );
    fd_ristretto255_point_t t1;
    FD_TEST( fd_ristretto255_point_frombytes( &t1, out1 ) == &t1 );
    FD_TEST( fd_ristretto255_point_eq( &t1, r1 ) );

    // must match original input
    FD_TEST( memcmp( out1, b1, 32 ) == 0 );

    // double round-trip tobytes(frombytes(tobytes(.)))
    uchar out1b[32] = { 0 };
    fd_ristretto255_point_t t1b;
    FD_TEST( fd_ristretto255_point_frombytes( &t1b, out1 ) == &t1b );
    fd_ristretto255_point_tobytes( out1b, &t1b );
    FD_TEST( memcmp( out1, out1b, 32 ) == 0 );
  } else {
    FD_TEST( r1 == NULL );
  }

  int p2_valid = fd_ristretto255_point_validate( b2 );
  FD_TEST( (r2 != NULL) == p2_valid );
  if( p2_valid ) {
    FD_TEST( r2 == &p2 );

    fd_ristretto255_point_tobytes( out2, r2 );
    FD_TEST( fd_ristretto255_point_validate( out2 ) );
    fd_ristretto255_point_t t2;
    FD_TEST( fd_ristretto255_point_frombytes( &t2, out2 ) == &t2 );
    FD_TEST( fd_ristretto255_point_eq( &t2, r2 ) );

    FD_TEST( memcmp( out2, b2, 32 ) == 0 );

    // double round-trip tobytes(frombytes(tobytes(.)))
    uchar out2b[32];
    fd_ristretto255_point_t t2b;
    FD_TEST( fd_ristretto255_point_frombytes( &t2b, out2 ) == &t2b );
    fd_ristretto255_point_tobytes( out2b, &t2b );
    FD_TEST( memcmp( out2, out2b, 32 ) == 0 );
  } else {
    FD_TEST( r2 == NULL );
  }

  if( !(p1_valid && p2_valid) ) return 0;

  // r == r
  FD_TEST( fd_ristretto255_point_eq( r1, r1 ) == 1 );
  FD_TEST( fd_ristretto255_point_eq( r2, r2 ) == 1 );

  // eq_neg (r,r) only if r is 0
  uchar z1[32] = { 0 }, z2[32] = { 0 };
  fd_ristretto255_point_tobytes( z1, r1 );
  fd_ristretto255_point_tobytes( z2, r2 );
  int r1_is_zero = (0==memcmp( z1, fd_ristretto255_compressed_zero, 32 ));
  int r2_is_zero = (0==memcmp( z2, fd_ristretto255_compressed_zero, 32 ));
  FD_TEST( fd_ristretto255_point_eq_neg( r1, r1 ) == r1_is_zero );
  FD_TEST( fd_ristretto255_point_eq_neg( r2, r2 ) == r2_is_zero );

  // r1 == r2 r2 == r1
  int e12  = fd_ristretto255_point_eq( r1, r2 );
  int e21  = fd_ristretto255_point_eq( r2, r1 );
  FD_TEST( e12 == e21 );

  // r1 eq_neg r2 r2 eq_neg r1
  int en12 = fd_ristretto255_point_eq_neg( r1, r2 );
  int en21 = fd_ristretto255_point_eq_neg( r2, r1 );
  FD_TEST( en12 == en21 );

  // if r1 == r2 encoding should be the same
  if( e12 ) {
    uchar e1[32] = { 0 }, e2[32] = { 0 };
    fd_ristretto255_point_tobytes( e1, r1 );
    fd_ristretto255_point_tobytes( e2, r2 );
    FD_TEST( memcmp( e1, e2, 32 ) == 0 );
  }

  // for nonzero points, eq and eq_neg cannot both be true.
  // if both are true, both must be zero
  if( e12 && en12 ) {
    FD_TEST( r1_is_zero && r2_is_zero );
    FD_TEST( memcmp( z1, fd_ristretto255_compressed_zero, 32 ) == 0 );
    FD_TEST( memcmp( z2, fd_ristretto255_compressed_zero, 32 ) == 0 );
  } else if( en12 && !e12 ) {
    // distinct negations should encode differently, except at zero
    FD_TEST( r1_is_zero || r2_is_zero || memcmp( z1, z2, 32 ) != 0 );
  }

  if( FD_UNLIKELY( size<128UL ) ) return 0;

  fd_ristretto255_hash_to_curve( &h1, data+64 );
  fd_ristretto255_map_to_curve ( &h2, data+64 );

  return 0;
}
