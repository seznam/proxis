enable_testing()

add_test(noredis test-noredis.sh)
add_test(nopass test-nopass.sh)
add_test(requirepass test-requirepass.sh)
add_test(cert test-cert.sh)
