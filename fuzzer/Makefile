EXTRA_DEFS=
# EXTRA_DEFS += -DREG_PROFILE # profile execution

DEFINES=
DEFINES += -DV8_EMBEDDED_BUILTINS
DEFINES += -DV8_GYP_BUILD
DEFINES += -DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64
DEFINES += -D__STDC_FORMAT_MACROS
DEFINES += -DOPENSSL_NO_PINSHARED
DEFINES += -DOPENSSL_THREADS
DEFINES += -DV8_TARGET_ARCH_X64
DEFINES += -DV8_EMBEDDER_STRING="-node.14"
DEFINES += -DENABLE_DISASSEMBLER
DEFINES += -DV8_PROMISE_INTERNAL_FIELD_COUNT=1
DEFINES += -DENABLE_MINOR_MC
DEFINES += -DV8_INTL_SUPPORT
DEFINES += -DV8_CONCURRENT_MARKING
DEFINES += -DV8_ARRAY_BUFFER_EXTENSION
DEFINES += -DV8_ENABLE_LAZY_SOURCE_POSITIONS
DEFINES += -DV8_USE_SIPHASH
DEFINES += -DDISABLE_UNTRUSTED_CODE_MITIGATIONS
DEFINES += -DV8_WIN64_UNWINDING_INFO
DEFINES += -DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH
DEFINES += -DV8_SNAPSHOT_COMPRESSION
DEFINES += -DUCONFIG_NO_SERVICE=1
DEFINES += -DU_ENABLE_DYLOAD=0
DEFINES += -DU_STATIC_IMPLEMENTATION=1
DEFINES += -DU_HAVE_STD_STRING=1
DEFINES += -DUCONFIG_NO_BREAK_ITERATION=0
DEFINES += -DDEBUG
DEFINES += -D_DEBUG
DEFINES += -DV8_ENABLE_CHECKS
DEFINES += -DOBJECT_PRINT
DEFINES += -DVERIFY_HEAP
DEFINES += -DV8_TRACE_MAPS
DEFINES += -DV8_ENABLE_ALLOCATION_TIMEOUT
DEFINES += -DV8_ENABLE_FORCE_SLOW_PATH
DEFINES += -DENABLE_HANDLE_ZAPPING

INCLUDES=
INCLUDES += -Imod
INCLUDES += -Ideps/v8
INCLUDES += -Ideps/v8/include

CFLAGS=-g -pthread -rdynamic -m64 ${DEFINES} ${INCLUDES}

LDFLAGS=

V8_DEPS=
V8_DEPS +=  build/node/out/Debug/obj.target/tools/icu/libicudata.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/icu/libicui18n.a
V8_DEPS +=  build/libicutools.a
V8_DEPS +=  build/libicuucx.a
V8_DEPS +=  build/node/out/Debug/obj.target/libnode.a
V8_DEPS +=  build/node/out/Debug/obj.target/libnode_text_start.a
V8_DEPS +=  build/libv8_base_without_compiler.a # contains regexp stuff to be patched, so we generate this ourselves
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_compiler.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_initializers.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_libsampler.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_snapshot.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_libbase.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_zlib.a
V8_DEPS +=  build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_libplatform.a

# I chose this commit rather arbitrarily, but I pin it here for stability
NODE_COMMIT=f645cc73185f1d690e82b01907e2c0da330a26de

.PHONY: all
all: build/fuzzer


.PHONY: clean
clean:
	if [ -d build/test ]; then rm -r build/test; fi;
	if [ -f build/tests ]; then rm build/tests; fi;
	if [ -f build/libicutools.a ]; then rm build/libicutools.a; fi;
	if [ -f build/libicuucx.a ]; then rm build/libicuucx.a; fi;
	rm build/*.o


.PHONY: test
test: build/tests
	./build/tests -r compact


.PHONY: copy_headers
copy_headers: node
	./copy_headers.py build/node


.PHONY: node
node: build/node/out/Debug/node


build/node/out/Debug/node: build/node/config.gypi
	$(MAKE) -C build/node -j4


build/node/config.gypi: build/node/.git
	cd build/node; git checkout ${NODE_COMMIT}; ./configure --debug


build/node/.git:
	mkdir -p build
	cd build; git clone https://github.com/nodejs/node.git


FUZZER_DEPS_FUZZ_CPPS:=$(wildcard src/fuzz/*.cpp)
FUZZER_DEPS_FUZZ_OS:=$(patsubst src/fuzz/%.cpp, build/%.o, $(FUZZER_DEPS_FUZZ_CPPS))

FUZZER_DEPS = build/main.o
FUZZER_DEPS += ${FUZZER_DEPS_FUZZ_OS}
FUZZER_DEPS += build/argument-parser.o
FUZZER_DEPS += build/regexp-executor.o
FUZZER_DEPS += build/flags.o
FUZZER_DEPS += build/fuzz-driver.o
FUZZER_DEPS += build/murmurhash.o
FUZZER_DEPS += build/interesting-char-finder.o

build/fuzzer: node ${FUZZER_DEPS} ${V8_DEPS} build/libv8_base_without_compiler.a
	mkdir -p build
	g++ -o $@ ${CFLAGS} -Wl,--start-group ${FUZZER_DEPS} -Wl,--end-group -Wl,--start-group ${V8_DEPS} -Wl,--end-group ${LDFLAGS}


build/main.o: src/main.cpp src/argument-parser.hpp src/regexp-executor.hpp src/fuzz-driver.hpp
	mkdir -p build
	g++ -c ${CFLAGS} -o $@ src/main.cpp


build/fuzz-driver.o: src/fuzz-driver.cpp src/fuzz-driver.hpp src/regexp-executor.hpp src/fuzz/corpus.hpp
	g++ -c ${CFLAGS} ${EXTRA_DEFS} -o $@ src/fuzz-driver.cpp


build/argument-parser.o: src/argument-parser.hpp src/argument-parser.cpp src/flags.hpp
	g++ -c ${CFLAGS} -Ideps/cxxopts -o $@ src/argument-parser.cpp


build/regexp-executor.o: src/regexp-executor.cpp src/regexp-executor.hpp src/fuzz/coverage-tracker.hpp
	g++ -c ${CFLAGS} -Isrc -o $@ src/regexp-executor.cpp

build/coverage-tracker.o: src/fuzz/coverage-tracker.cpp src/fuzz/coverage-tracker.hpp
	g++ -c ${CFLAGS} -Ideps/murmurhash -o $@ src/fuzz/coverage-tracker.cpp

build/corpus.o: src/fuzz/corpus.cpp src/fuzz/corpus.hpp src/fuzz/coverage-tracker.hpp
	g++ -c ${CFLAGS} -o $@ src/fuzz/corpus.cpp

build/mutations.o: src/fuzz/mutations.cpp src/fuzz/mutations.hpp
	g++ -c ${CFLAGS} -o $@ src/fuzz/mutations.cpp

build/flags.o: src/flags.hpp src/flags.cpp
	g++ -c ${CFLAGS} -o $@ src/flags.cpp

build/interesting-char-finder.o: src/interesting-char-finder.cpp src/interesting-char-finder.hpp src/regexp-executor.hpp
	g++ -c ${CFLAGS} -o $@ src/interesting-char-finder.cpp

build/murmurhash.o: deps/murmurhash/murmur3.c deps/murmurhash/murmur3.h
	gcc -c ${CFLAGS} -Ideps/murmurhash -O3 -o $@ deps/murmurhash/murmur3.c


V8_MOD_DEPS = build/regexp-macro-assembler.o
V8_MOD_DEPS += build/regexp-interpreter.o
V8_MOD_DEPS += build/regexp.o
build/libv8_base_without_compiler.a: ${V8_MOD_DEPS} build/regexp-macro-assembler.o build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_base_without_compiler.a
	if [ -f $@ ]; then rm $@; fi;
	ar -rcsT build/libv8_base_without_compiler.a build/node/out/Debug/obj.target/tools/v8_gypfiles/libv8_base_without_compiler.a
	ar -rsTv build/libv8_base_without_compiler.a ${V8_MOD_DEPS}


build/regexp-interpreter.o: mod/src/regexp/regexp-interpreter.cc mod/src/regexp/regexp-interpreter.h src/fuzz/coverage-tracker.hpp
	g++ -g -c -o $@ mod/src/regexp/regexp-interpreter.cc '-DV8_EMBEDDED_BUILTINS' '-DV8_GYP_BUILD' '-DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DV8_TARGET_ARCH_X64' '-DV8_EMBEDDER_STRING="-node.19"' '-DENABLE_DISASSEMBLER' '-DV8_PROMISE_INTERNAL_FIELD_COUNT=1' '-DENABLE_MINOR_MC' '-DV8_INTL_SUPPORT' '-DV8_CONCURRENT_MARKING' '-DV8_ARRAY_BUFFER_EXTENSION' '-DV8_ENABLE_LAZY_SOURCE_POSITIONS' '-DV8_USE_SIPHASH' '-DDISABLE_UNTRUSTED_CODE_MITIGATIONS' '-DV8_WIN64_UNWINDING_INFO' '-DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH' '-DV8_SNAPSHOT_COMPRESSION' '-DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_STATIC_IMPLEMENTATION=1' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' '-DOBJECT_PRINT' '-DVERIFY_HEAP' '-DV8_TRACE_MAPS' '-DV8_ENABLE_ALLOCATION_TIMEOUT' '-DV8_ENABLE_FORCE_SLOW_PATH' '-DENABLE_HANDLE_ZAPPING' -Imod -Isrc -Ideps/v8 -Ibuild/node/deps/icu-small/source/common -pthread -Wno-unused-parameter -m64 -Wno-return-type -fno-strict-aliasing -m64 -g -Woverloaded-virtual -fdata-sections -ffunction-sections -O3 -fno-rtti -fno-exceptions -std=gnu++1y


build/regexp-macro-assembler.o: mod/src/regexp/regexp-macro-assembler.cc mod/src/regexp/regexp-macro-assembler.h
	g++ -g -c '-DV8_EMBEDDED_BUILTINS' '-DV8_GYP_BUILD' '-DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DV8_TARGET_ARCH_X64' '-DV8_EMBEDDER_STRING="-node.19"' '-DENABLE_DISASSEMBLER' '-DV8_PROMISE_INTERNAL_FIELD_COUNT=1' '-DENABLE_MINOR_MC' '-DV8_INTL_SUPPORT' '-DV8_CONCURRENT_MARKING' '-DV8_ARRAY_BUFFER_EXTENSION' '-DV8_ENABLE_LAZY_SOURCE_POSITIONS' '-DV8_USE_SIPHASH' '-DDISABLE_UNTRUSTED_CODE_MITIGATIONS' '-DV8_WIN64_UNWINDING_INFO' '-DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH' '-DV8_SNAPSHOT_COMPRESSION' '-DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_STATIC_IMPLEMENTATION=1' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' '-DOBJECT_PRINT' '-DVERIFY_HEAP' '-DV8_TRACE_MAPS' '-DV8_ENABLE_ALLOCATION_TIMEOUT' '-DV8_ENABLE_FORCE_SLOW_PATH' '-DENABLE_HANDLE_ZAPPING' -Imod -Ideps/v8 -Ibuild/node/deps/icu-small/source/common -o $@ mod/src/regexp/regexp-macro-assembler.cc


build/regexp.o: mod/src/regexp/regexp.cc mod/src/regexp/regexp.h
	g++ -g -c '-DV8_EMBEDDED_BUILTINS' '-DV8_GYP_BUILD' '-DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DV8_TARGET_ARCH_X64' '-DV8_EMBEDDER_STRING="-node.19"' '-DENABLE_DISASSEMBLER' '-DV8_PROMISE_INTERNAL_FIELD_COUNT=1' '-DENABLE_MINOR_MC' '-DV8_INTL_SUPPORT' '-DV8_CONCURRENT_MARKING' '-DV8_ARRAY_BUFFER_EXTENSION' '-DV8_ENABLE_LAZY_SOURCE_POSITIONS' '-DV8_USE_SIPHASH' '-DDISABLE_UNTRUSTED_CODE_MITIGATIONS' '-DV8_WIN64_UNWINDING_INFO' '-DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH' '-DV8_SNAPSHOT_COMPRESSION' '-DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_STATIC_IMPLEMENTATION=1' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' '-DOBJECT_PRINT' '-DVERIFY_HEAP' '-DV8_TRACE_MAPS' '-DV8_ENABLE_ALLOCATION_TIMEOUT' '-DV8_ENABLE_FORCE_SLOW_PATH' '-DENABLE_HANDLE_ZAPPING' -Imod -Isrc -Ideps/v8 -Ibuild/node/deps/icu-small/source/common -pthread -Wno-unused-parameter -m64 -Wno-return-type -fno-strict-aliasing -m64 -fno-omit-frame-pointer -fdata-sections -ffunction-sections -fno-rtti -fno-exceptions -std=gnu++1y -o $@ mod/src/regexp/regexp.cc


ICU_MOD_DEPS = build/ustrcase.o
ICU_MOD_DEPS += build/unistr_case.o
build/libicutools.a: ${ICU_MOD_DEPS} build/node/out/Debug/obj.host/tools/icu/libicutools.a
	if [ -f $@ ]; then rm $@; fi;
	ar -rcsT build/libicutools.a build/node/out/Debug/obj.host/tools/icu/libicutools.a
	ar -rsTv build/libicutools.a ${ICU_MOD_DEPS}


build/libicuucx.a: ${ICU_MOD_DEPS} build/node/out/Debug/obj.target/tools/icu/libicuucx.a
	if [ -f $@ ]; then rm $@; fi;
	ar -rcsT build/libicuucx.a build/node/out/Debug/obj.target/tools/icu/libicuucx.a
	ar -rsTv build/libicuucx.a ${ICU_MOD_DEPS}


build/ustrcase.o: mod/ustrcase.cpp mod/unicode/unistr.h
	g++ -g -c -o $@ '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DU_COMMON_IMPLEMENTATION=1' '-DU_ATTRIBUTE_DEPRECATED=' '-D_CRT_SECURE_NO_DEPRECATE=' '-DU_STATIC_IMPLEMENTATION=1' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' -Imod -Ibuild/node/deps/icu-small/source/common -pthread -Wall -Wextra -Wno-unused-parameter -m64 -Wno-deprecated-declarations -Wno-strict-aliasing -O0 -fno-exceptions -std=gnu++1y -frtti mod/ustrcase.cpp


build/unistr_case.o: mod/unistr_case.cpp mod/unicode/unistr.h
	g++ -g -c -o $@ '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DU_COMMON_IMPLEMENTATION=1' '-DU_I18N_IMPLEMENTATION=1' '-DU_IO_IMPLEMENTATION=1' '-DU_TOOLUTIL_IMPLEMENTATION=1' '-DU_ATTRIBUTE_DEPRECATED=' '-D_CRT_SECURE_NO_DEPRECATE=' '-DU_STATIC_IMPLEMENTATION=1' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' -Imod -Ibuild/node/deps/icu-small/source/common -pthread -Wall -Wextra -Wno-unused-parameter -m64 -Wno-deprecated-declarations -Wno-strict-aliasing -O0 -fno-exceptions -std=gnu++1y -frtti mod/unistr_case.cpp


TEST_FILES:=$(wildcard test/test-*.cpp)
TEST_OBJECTS:=$(patsubst test/%.cpp, build/test/%.o, $(TEST_FILES))

TEST_DEPS=build/regexp-executor.o
TEST_DEPS += build/coverage-tracker.o
TEST_DEPS += build/corpus.o
TEST_DEPS += build/murmurhash.o
TEST_DEPS += build/mutations.o
TEST_DEPS += build/interesting-char-finder.o
TEST_DEPS += build/flags.o

build/tests: ${TEST_OBJECTS} ${V8_DEPS} build/test/main.o ${TEST_DEPS}
	g++ -g -o $@ -Itest ${CFLAGS} ${TEST_DEPS} -Wl,--start-group ${V8_DEPS} -Wl,--end-group ${TEST_OBJECTS} build/test/main.o


build/test/%.o: test/%.cpp test/catch.hpp
	mkdir -p build/test
	g++ -g -c -Isrc ${CFLAGS} -o $@ $<
