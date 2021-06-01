// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Portions of this file Copyright 2020 Robert McLaughlin <robert349@ucsb.edu>,
//   demarcated by ------- mod_mcl_2020 -------
// 

// A simple interpreter for the Irregexp byte code.

#ifndef V8_REGEXP_REGEXP_INTERPRETER_H_
#define V8_REGEXP_REGEXP_INTERPRETER_H_

#include "src/regexp/regexp.h"
#include "fuzz/coverage-tracker.hpp"

#include <vector>

namespace v8 {
namespace internal {


class V8_EXPORT_PRIVATE IrregexpInterpreter : public AllStatic {
 public:
  enum Result {
    FAILURE = RegExp::kInternalRegExpFailure,
    SUCCESS = RegExp::kInternalRegExpSuccess,
    EXCEPTION = RegExp::kInternalRegExpException,
    RETRY = RegExp::kInternalRegExpRetry,
  };

  // ------- mod_mcl_2020 -------
  // In case a StackOverflow occurs, a StackOverflowException is created and
  // EXCEPTION is returned.
  static Result MatchForCallFromRuntime(Isolate* isolate,
                                        Handle<JSRegExp> regexp,
                                        Handle<String> subject_string,
                                        int* registers, int registers_length,
                                        int start_position,
                                        int32_t max_total,
#if defined REG_COUNT_PATHLENGTH
                                        uint64_t max_path,
#endif
                                        regulator::fuzz::CoverageTracker *coverage_tracker);
  
  static Result MatchForCallFromRuntime(Isolate* isolate,
                                        Handle<JSRegExp> regexp,
                                        Handle<String> subject_string,
                                        int* registers, int registers_length,
                                        int start_position);
  // ------- (end) mod_mcl_2020 -------

  // In case a StackOverflow occurs, EXCEPTION is returned. The caller is
  // responsible for creating the exception.
  // RETRY is returned if a retry through the runtime is needed (e.g. when
  // interrupts have been scheduled or the regexp is marked for tier-up).
  // Arguments input_start, input_end and backtrack_stack are
  // unused. They are only passed to match the signature of the native irregex
  // code.
  static Result MatchForCallFromJs(Address subject, int32_t start_position,
                                   Address input_start, Address input_end,
                                   int* registers, int32_t registers_length,
                                   Address backtrack_stack,
                                   RegExp::CallOrigin call_origin,
                                   Isolate* isolate, Address regexp);

  // ------- mod_mcl_2020 -------

  static Result MatchInternal(Isolate* isolate, ByteArray code_array,
                              String subject_string, int* registers,
                              int registers_length, int start_position,
                              RegExp::CallOrigin call_origin,
                              uint32_t backtrack_limit);

  static Result MatchInternal(Isolate* isolate, ByteArray code_array,
                              String subject_string, int* registers,
                              int registers_length, int start_position,
                              RegExp::CallOrigin call_origin,
                              uint32_t backtrack_limit,
                              int32_t max_total,
#if defined REG_COUNT_PATHLENGTH
                              uint64_t max_path,
#endif
                              regulator::fuzz::CoverageTracker *coverage_tracker);

  // ------- (end) mod_mcl_2020 -------

 private:

  // ------- mod_mcl_2020 -------

  static Result Match(Isolate* isolate, JSRegExp regexp, String subject_string,
                      int* registers, int registers_length, int start_position,
                      RegExp::CallOrigin call_origin, int32_t max_total,
#if defined REG_COUNT_PATHLENGTH
                      uint64_t max_path,
#endif
                      regulator::fuzz::CoverageTracker *coverage_tracker);

  static Result Match(Isolate* isolate, JSRegExp regexp, String subject_string,
                      int* registers, int registers_length, int start_position,
                      RegExp::CallOrigin call_origin);

  // ------- (end) mod_mcl_2020 -------

};

}  // namespace internal
}  // namespace v8

#endif  // V8_REGEXP_REGEXP_INTERPRETER_H_
