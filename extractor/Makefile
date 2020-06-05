LDFLAGS=-lpthread -licui18n -licuuc -lm -ldl
GCCFLAGS=-g -m64 -pthread -rdynamic -Iinclude/v8/include -Iinclude/v8
GCCFLAGS += -DDEBUG
GCCFLAGS += -D_DEBUG
GCCFLAGS += -DV8_INTL_SUPPORT
GCCFLAGS += -DOBJECT_PRINT
GCCFLAGS += -DVERIFY_HEAP

V8_DEPS=
V8_DEPS +=  deps/libicudata.a
V8_DEPS +=  deps/libicui18n.a
V8_DEPS +=  deps/libicutools.a
V8_DEPS +=  deps/libicuucx.a
V8_DEPS +=  deps/node_v8/libnode.a
V8_DEPS +=  deps/node_v8/libnode_text_start.a
V8_DEPS +=  deps/node_v8/libv8_base_without_compiler.a
V8_DEPS +=  deps/node_v8/libv8_compiler.a
V8_DEPS +=  deps/node_v8/libv8_initializers.a
V8_DEPS +=  deps/node_v8/libv8_libsampler.a
V8_DEPS +=  deps/node_v8/libv8_snapshot.a
V8_DEPS +=  deps/node_v8/libv8_libbase.a
V8_DEPS +=  deps/node_v8/libv8_zlib.a
V8_DEPS +=  deps/node_v8/libv8_libplatform.a


.PHONY: all
all: bin/extractor

.PHONY: clean
clean:
	rm bin/extractor


bin/extractor: src/main.cpp ${V8_DEPS} bin/argument_parser.o
	mkdir -p bin
	g++ ${GCCFLAGS} -o $@ src/main.cpp bin/argument_parser.o -Wl,--start-group ${V8_DEPS} ${LDFLAGS} -Wl,--end-group


bin/argument_parser.o: src/argument_parser.hpp src/argument_parser.cpp
	mkdir -p bin
	g++ ${GCCFLAGS} -c -o bin/argument_parser.o src/argument_parser.cpp
