$(call add-hdrs,fd_utf8.h)
$(call add-objs,fd_utf8,fd_ballet)
$(call make-unit-test,test_utf8,test_utf8,fd_ballet fd_util)
$(call run-unit-test,test_utf8)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_utf8_verify,fuzz_utf8_verify,fd_ballet fd_util)
endif