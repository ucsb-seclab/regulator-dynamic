CXX=g++
CC=gcc

BUILDDIR=build/
DEPDIR=$(BUILDDIR)deps/

# EXTRA_DEFS += -DREG_PROFILE # profile execution

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

DEFINES += ${EXTRA_DEFS}

INCLUDES += -Isrc
INCLUDES += -Imod
INCLUDES += -Ideps/from_node/v8
INCLUDES += -Ideps/from_node/v8/include
INCLUDES += -Ideps/murmurhash
INCLUDES += -Ideps/cxxopts
INCLUDES += -Ideps/from_node/icu-small/source/common

CPPFLAGS=-g -pthread -rdynamic -m64 -O3 ${DEFINES} ${INCLUDES}

LDFLAGS=

# The not-patched *.a files from Node that will never be patched
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/icu/libicudata.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/icu/libicui18n.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/libnode.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/libnode_text_start.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_compiler.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_initializers.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_libsampler.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_snapshot.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_libbase.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_zlib.a
V8_DEPS_UNPATCHED +=  $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_libplatform.a

# The stuff we need for patching
V8_DEPS_TO_PATCH += $(BUILDDIR)node/out/Debug/obj.host/tools/icu/libicutools.a
V8_DEPS_TO_PATCH += $(BUILDDIR)node/out/Debug/obj.target/tools/icu/libicuucx.a
V8_DEPS_TO_PATCH += $(BUILDDIR)node/out/Debug/obj.target/tools/v8_gypfiles/libv8_base_without_compiler.a

# construct the whole list of v8 deps we need at compile time
V8_DEPS += $(patsubst %, $(BUILDDIR)node_libs/%, $(notdir $(V8_DEPS_UNPATCHED)))
V8_DEPS += $(patsubst %, $(BUILDDIR)%, $(notdir $(V8_DEPS_TO_PATCH)))

# the stuff we need to keep around for patching, compilation, etc ...
V8_DEPS_UNPATCHED_DEST := $(patsubst %, $(BUILDDIR)node_libs/%, $(notdir $(V8_DEPS_UNPATCHED)))
V8_DEPS_UNPATCHED_DEST += $(patsubst %, $(BUILDDIR)node_libs/%, $(notdir $(V8_DEPS_TO_PATCH)))


# add more

# I chose this commit rather arbitrarily, but I pin it here for stability
NODE_COMMIT=f645cc73185f1d690e82b01907e2c0da330a26de

.PHONY: all
all: $(BUILDDIR)fuzzer_stripped


.PHONY: clean
clean:
	if [ -d $(BUILDDIR)test ]; then rm -vr $(BUILDDIR)test; fi;
	if [ -f $(BUILDDIR)tests ]; then rm -v $(BUILDDIR)tests; fi;
	if [ -f $(BUILDDIR)libicutools.a ]; then rm -v $(BUILDDIR)libicutools.a; fi;
	if [ -f $(BUILDDIR)libicuucx.a ]; then rm -v $(BUILDDIR)libicuucx.a; fi;
	if [ -f $(BUILDDIR)libv8_base_without_compiler.a ]; then rm -v $(BUILDDIR)libv8_base_without_compiler.a; fi;
	if [ -d $(BUILDDIR)objects ]; then rm -vr $(BUILDDIR)objects; fi;
	if [ -d $(BUILDDIR)deps ]; then rm -vr $(BUILDDIR)deps; fi;
	rm build/*.o

.PHONY: test
test: $(BUILDDIR)tests
	./$(BUILDDIR)tests -r compact

#
# Procedures to checkout & make nodejs
#

.PHONY: node
node: $(V8_DEPS_UNPATCHED_DEST) deps/from_node/


deps/from_node/: $(BUILDDIR)node/out/Debug/node
	if [ -d deps/from_node.tmp ]; then rm -rv deps/from_node.tmp; fi;
	./copy_headers.py -o deps/from_node.tmp $(BUILDDIR)node
	mv deps/from_node.tmp deps/from_node


$(V8_DEPS_UNPATCHED_DEST): $(BUILDDIR)node/out/Debug/node
	mkdir -p $(BUILDDIR)node_libs
	for f in $(V8_DEPS_UNPATCHED) $(V8_DEPS_TO_PATCH) ; do \
		if [ -f $(BUILDDIR)node_libs/`basename $$f` ]; then rm -v $(BUILDDIR)node_libs/`basename $$f` ; fi ; \
		ar -t $$f | xargs ar -rcs $(BUILDDIR)node_libs/`basename $$f` ; \
	done


.SECONDARY: $(BUILDDIR)node/out/Debug/node
$(BUILDDIR)node/out/Debug/node: $(BUILDDIR)node/config.gypi
	$(MAKE) -C $(BUILDDIR)node

.SECONDARY: $(BUILDDIR)node/config.gypi
$(BUILDDIR)node/config.gypi: $(BUILDDIR)node/.git
	cd $(BUILDDIR)node; git checkout ${NODE_COMMIT}; ./configure --debug


.SECONDARY: $(BUILDDIR)node/.git
$(BUILDDIR)node/.git:
	mkdir -p $(BUILDDIR)node
	cd $(BUILDDIR)node; git init
	cd $(BUILDDIR)node; git remote add origin https://github.com/nodejs/node.git
	cd $(BUILDDIR)node; git fetch origin --depth=1 ${NODE_COMMIT}
	cd $(BUILDDIR)node; git reset --hard FETCH_HEAD


FUZZER_DEPS_CPPS:=$(shell find src -type f -name "*.cpp")
FUZZER_DEPS_OS:=$(patsubst src/%.cpp, $(BUILDDIR)objects/%.o, $(FUZZER_DEPS_CPPS))

FUZZER_DEPS_OS += $(BUILDDIR)murmurhash.o


$(BUILDDIR)fuzzer: deps/from_node/ ${FUZZER_DEPS_OS} ${V8_DEPS}
	mkdir -p build
	$(CXX) -o $@ ${CPPFLAGS} -Wl,--start-group ${FUZZER_DEPS_OS} -Wl,--end-group -Wl,--start-group ${V8_DEPS} -Wl,--end-group ${LDFLAGS}


$(BUILDDIR)fuzzer_stripped: $(BUILDDIR)fuzzer
	strip -s -o $@ $<


$(BUILDDIR)objects/%.o: src/%.cpp $(DEPDIR)/%.d | $(DEPDIR)
	@mkdir -p $(@D)
	@mkdir -p $(dir $(DEPDIR)$*.d)
	$(CXX) -c -o $@ ${CPPFLAGS} -MT $@ -MMD -MP -MF $(DEPDIR)$*.d $<

$(DEPDIR):
	mkdir -p $@

# Makes directories
%/:
	mkdir -p $@


$(BUILDDIR)murmurhash.o: deps/murmurhash/murmur3.c deps/murmurhash/murmur3.h
	$(CC) -c ${CFLAGS} -Ideps/murmurhash -O3 -o $@ deps/murmurhash/murmur3.c


V8_MOD_DEPS += $(BUILDDIR)regexp-macro-assembler.o
V8_MOD_DEPS += $(BUILDDIR)regexp-interpreter.o
V8_MOD_DEPS += $(BUILDDIR)regexp.o
$(BUILDDIR)libv8_base_without_compiler.a: ${V8_MOD_DEPS} $(BUILDDIR)regexp-macro-assembler.o $(BUILDDIR)node_libs/libv8_base_without_compiler.a
	if [ -f $@ ]; then rm $@; fi;
	ar -rcsT $(BUILDDIR)libv8_base_without_compiler.a $(BUILDDIR)node_libs/libv8_base_without_compiler.a
	ar -rsTv $(BUILDDIR)libv8_base_without_compiler.a ${V8_MOD_DEPS}


$(BUILDDIR)regexp-interpreter.o: mod/src/regexp/regexp-interpreter.cc mod/src/regexp/regexp-interpreter.h src/fuzz/coverage-tracker.hpp
	$(CXX) -g -c -o $@ mod/src/regexp/regexp-interpreter.cc '-DV8_EMBEDDED_BUILTINS' '-DV8_GYP_BUILD' '-DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DV8_TARGET_ARCH_X64' '-DV8_EMBEDDER_STRING="-node.19"' '-DENABLE_DISASSEMBLER' '-DV8_PROMISE_INTERNAL_FIELD_COUNT=1' '-DENABLE_MINOR_MC' '-DV8_INTL_SUPPORT' '-DV8_CONCURRENT_MARKING' '-DV8_ARRAY_BUFFER_EXTENSION' '-DV8_ENABLE_LAZY_SOURCE_POSITIONS' '-DV8_USE_SIPHASH' '-DDISABLE_UNTRUSTED_CODE_MITIGATIONS' '-DV8_WIN64_UNWINDING_INFO' '-DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH' '-DV8_SNAPSHOT_COMPRESSION' '-DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_STATIC_IMPLEMENTATION=1' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' '-DOBJECT_PRINT' '-DVERIFY_HEAP' '-DV8_TRACE_MAPS' '-DV8_ENABLE_ALLOCATION_TIMEOUT' '-DV8_ENABLE_FORCE_SLOW_PATH' '-DENABLE_HANDLE_ZAPPING' -Imod -Isrc -Ideps/from_node/v8 -Ideps/from_node/icu-small/source/common -pthread -Wno-unused-parameter -m64 -Wno-return-type -fno-strict-aliasing -m64 -g -Woverloaded-virtual -fdata-sections -ffunction-sections -fno-rtti -fno-exceptions -std=gnu++1y


$(BUILDDIR)regexp-macro-assembler.o: mod/src/regexp/regexp-macro-assembler.cc mod/src/regexp/regexp-macro-assembler.h
	$(CXX) -g -c '-DV8_EMBEDDED_BUILTINS' '-DV8_GYP_BUILD' '-DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DV8_TARGET_ARCH_X64' '-DV8_EMBEDDER_STRING="-node.19"' '-DENABLE_DISASSEMBLER' '-DV8_PROMISE_INTERNAL_FIELD_COUNT=1' '-DENABLE_MINOR_MC' '-DV8_INTL_SUPPORT' '-DV8_CONCURRENT_MARKING' '-DV8_ARRAY_BUFFER_EXTENSION' '-DV8_ENABLE_LAZY_SOURCE_POSITIONS' '-DV8_USE_SIPHASH' '-DDISABLE_UNTRUSTED_CODE_MITIGATIONS' '-DV8_WIN64_UNWINDING_INFO' '-DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH' '-DV8_SNAPSHOT_COMPRESSION' '-DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_STATIC_IMPLEMENTATION=1' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' '-DOBJECT_PRINT' '-DVERIFY_HEAP' '-DV8_TRACE_MAPS' '-DV8_ENABLE_ALLOCATION_TIMEOUT' '-DV8_ENABLE_FORCE_SLOW_PATH' '-DENABLE_HANDLE_ZAPPING' -Isrc -Imod -Ideps/from_node/v8 -Ideps/from_node/icu-small/source/common -o $@ mod/src/regexp/regexp-macro-assembler.cc


$(BUILDDIR)regexp.o: mod/src/regexp/regexp.cc mod/src/regexp/regexp.h
	$(CXX) -g -c '-DV8_EMBEDDED_BUILTINS' '-DV8_GYP_BUILD' '-DV8_TYPED_ARRAY_MAX_SIZE_IN_HEAP=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DV8_TARGET_ARCH_X64' '-DV8_EMBEDDER_STRING="-node.19"' '-DENABLE_DISASSEMBLER' '-DV8_PROMISE_INTERNAL_FIELD_COUNT=1' '-DENABLE_MINOR_MC' '-DV8_INTL_SUPPORT' '-DV8_CONCURRENT_MARKING' '-DV8_ARRAY_BUFFER_EXTENSION' '-DV8_ENABLE_LAZY_SOURCE_POSITIONS' '-DV8_USE_SIPHASH' '-DDISABLE_UNTRUSTED_CODE_MITIGATIONS' '-DV8_WIN64_UNWINDING_INFO' '-DV8_ENABLE_REGEXP_INTERPRETER_THREADED_DISPATCH' '-DV8_SNAPSHOT_COMPRESSION' '-DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_STATIC_IMPLEMENTATION=1' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' '-DOBJECT_PRINT' '-DVERIFY_HEAP' '-DV8_TRACE_MAPS' '-DV8_ENABLE_ALLOCATION_TIMEOUT' '-DV8_ENABLE_FORCE_SLOW_PATH' '-DENABLE_HANDLE_ZAPPING' -Imod -Isrc -Ideps/from_node/v8 -Ideps/from_node/icu-small/source/common -pthread -Wno-unused-parameter -m64 -Wno-return-type -fno-strict-aliasing -m64 -fno-omit-frame-pointer -fdata-sections -ffunction-sections -fno-rtti -fno-exceptions -std=gnu++1y -o $@ mod/src/regexp/regexp.cc


ICU_MOD_DEPS = $(BUILDDIR)ustrcase.o
ICU_MOD_DEPS += $(BUILDDIR)unistr_case.o
$(BUILDDIR)libicutools.a: ${ICU_MOD_DEPS} $(BUILDDIR)node_libs/libicutools.a
	if [ -f $@ ]; then rm $@; fi;
	ar -rcsT $(BUILDDIR)libicutools.a $(BUILDDIR)node_libs/libicutools.a
	ar -rsTv $(BUILDDIR)libicutools.a ${ICU_MOD_DEPS}


$(BUILDDIR)libicuucx.a: ${ICU_MOD_DEPS} $(BUILDDIR)node_libs/libicuucx.a
	if [ -f $@ ]; then rm $@; fi;
	ar -rcsT $(BUILDDIR)libicuucx.a $(BUILDDIR)node_libs/libicuucx.a
	ar -rsTv $(BUILDDIR)libicuucx.a ${ICU_MOD_DEPS}


$(BUILDDIR)ustrcase.o: mod/ustrcase.cpp mod/unicode/unistr.h
	$(CXX) -g -c -o $@ '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DU_COMMON_IMPLEMENTATION=1' '-DU_ATTRIBUTE_DEPRECATED=' '-D_CRT_SECURE_NO_DEPRECATE=' '-DU_STATIC_IMPLEMENTATION=1' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' -Imod -Ideps/from_node/icu-small/source/common -pthread -Wall -Wextra -Wno-unused-parameter -m64 -Wno-deprecated-declarations -Wno-strict-aliasing -O0 -fno-exceptions -std=gnu++1y -frtti mod/ustrcase.cpp


$(BUILDDIR)unistr_case.o: mod/unistr_case.cpp mod/unicode/unistr.h
	$(CXX) -g -c -o $@ '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DU_COMMON_IMPLEMENTATION=1' '-DU_I18N_IMPLEMENTATION=1' '-DU_IO_IMPLEMENTATION=1' '-DU_TOOLUTIL_IMPLEMENTATION=1' '-DU_ATTRIBUTE_DEPRECATED=' '-D_CRT_SECURE_NO_DEPRECATE=' '-DU_STATIC_IMPLEMENTATION=1' '-DUCONFIG_NO_SERVICE=1' '-DU_ENABLE_DYLOAD=0' '-DU_HAVE_STD_STRING=1' '-DUCONFIG_NO_BREAK_ITERATION=0' '-DDEBUG' '-D_DEBUG' '-DV8_ENABLE_CHECKS' -Imod -Ideps/from_node/icu-small/source/common -pthread -Wall -Wextra -Wno-unused-parameter -m64 -Wno-deprecated-declarations -Wno-strict-aliasing -O0 -fno-exceptions -std=gnu++1y -frtti mod/unistr_case.cpp


TEST_CPPS:=$(shell find test -type f -name "*.cpp")
TEST_OS:=$(patsubst test/%.cpp, $(BUILDDIR)test/%.o, $(TEST_CPPS))
TEST_OS_PLUS_FUZZER_DEPS := $(TEST_OS) $(filter-out $(BUILDDIR)objects/main.o, $(FUZZER_DEPS_OS))


$(BUILDDIR)tests: ${V8_DEPS} deps/from_node/ ${TEST_OS_PLUS_FUZZER_DEPS}
	@echo ${TEST_OS}
	$(CXX) -g -o $@ -Itest ${CPPFLAGS} -Wl,--start-group ${TEST_OS_PLUS_FUZZER_DEPS} -Wl,--end-group -Wl,--start-group ${V8_DEPS} -Wl,--end-group


$(BUILDDIR)test/%.o: test/%.cpp $(BUILDDIR)test/%.d
	@mkdir -p $(@D)
	@mkdir -p $(dir $(BUILDDIR)/test$*.d)
	$(CXX) -c -o $@ ${CPPFLAGS} -MT $@ -MMD -MP -MF $(BUILDDIR)test/$*.d $<

#
# Dependency tracking stuff
#
# See: http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
#

FUZZER_DEPS_DS:=$(patsubst src/%.cpp, $(DEPDIR)/%.d, $(FUZZER_DEPS_CPPS))
$(FUZZER_DEPS_DS):

TEST_DEPS_DS:=$(patsubst test/%.cpp, $(BUILDDIR)test/%.d, $(TEST_CPPS))
$(TEST_DEPS_DS):

include $(wildcard $(FUZZER_DEPS_DS))
include $(wildcard $(TEST_DEPS_DS))
