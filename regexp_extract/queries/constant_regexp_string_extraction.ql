/**
 * @kind path-problem
 * @problem.severity error
 */

import javascript
import semmle.javascript.dataflow.InferredTypes
import semmle.javascript.security.dataflow.RegExpInjectionCustomizations::RegExpInjection

/**
 * Holds if `source` may be interpreted as a regular expression.
 * Makes use of built-in query, plus adds knowledge of String.prototype.matchAll()
 * calls
 */
predicate isInterpretedAsRegExp2(DataFlow::Node source) {
  isInterpretedAsRegExp(source) or
  (
    exists(DataFlow::MethodCallNode mce |
      mce.getReceiver().analyze().getAType() = TTString() and
      mce.getMethodName() = "matchAll" and
      mce.getNumArgument() = 1 and
      mce.getArgument(0) = source)
  )
}


// I'm not sure how to make this work without violating 'non-monotonic recursion'
// restriction
string templateConstantVal(TemplateLiteral tl)
{
  (tl.getNumElement() = 0 and result = "") or
  (tl.getNumElement() = 1 and
    result = stringConstantVal(tl.getElement(0))
  ) or
  (tl.getNumElement() = 2 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1))
    )
  ) or
  (tl.getNumElement() = 3 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2))
    )
  ) or
  (tl.getNumElement() = 4 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2)) +
      stringConstantVal(tl.getElement(3))
    )
  ) or
  (tl.getNumElement() = 5 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2)) +
      stringConstantVal(tl.getElement(3)) +
      stringConstantVal(tl.getElement(4))
    )
  ) or
  (tl.getNumElement() = 6 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2)) +
      stringConstantVal(tl.getElement(3)) +
      stringConstantVal(tl.getElement(4)) +
      stringConstantVal(tl.getElement(5))
    )
  ) or
  (tl.getNumElement() = 7 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2)) +
      stringConstantVal(tl.getElement(3)) +
      stringConstantVal(tl.getElement(4)) +
      stringConstantVal(tl.getElement(5)) +
      stringConstantVal(tl.getElement(6))
    )
  ) or
  (tl.getNumElement() = 8 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2)) +
      stringConstantVal(tl.getElement(3)) +
      stringConstantVal(tl.getElement(4)) +
      stringConstantVal(tl.getElement(5)) +
      stringConstantVal(tl.getElement(6)) +
      stringConstantVal(tl.getElement(7))
    )
  ) or
  (tl.getNumElement() = 9 and
    result = (
      stringConstantVal(tl.getElement(0)) +
      stringConstantVal(tl.getElement(1)) +
      stringConstantVal(tl.getElement(2)) +
      stringConstantVal(tl.getElement(3)) +
      stringConstantVal(tl.getElement(4)) +
      stringConstantVal(tl.getElement(5)) +
      stringConstantVal(tl.getElement(6)) +
      stringConstantVal(tl.getElement(7)) +
      stringConstantVal(tl.getElement(8))
    )
  )
}

string stringConstantVal(Expr exp)
{
  (exp instanceof ConstantString and
    result = exp.(ConstantString).getStringValue()) or

  (exp instanceof VarUse and
    // to avoid making mistakes
    (
      not exists(Assignment assignment |
        assignment.getTarget().(VarUse).getSsaVariable() = exp.(VarUse).getSsaVariable()
      )
    ) and
    result = stringConstantVal(exp.(VarUse).getVariable().getAnAssignedExpr())) or

  (exp instanceof AddExpr and
    result = (
      stringConstantVal(exp.(AddExpr).getLeftOperand()) +
      stringConstantVal(exp.(AddExpr).getRightOperand())
    )) or

  (exp instanceof PropAccess and
  (
      exp.(PropAccess).getPropertyName() = "source" and
      exists(Expr base |
        exp.(PropAccess).accesses(base, "source") and
        base.analyze().getAType() = TTRegExp() and
        // only handle one cases here for now...
        // 1. /someliteral/.source
        (
          result = base.(RegExpLiteral).getRoot().getRawValue()
        )
        // not implemented...
        // 2. const x = /someliteral/; new RegExp(x.source);
      )
  )) or

  (exp instanceof TemplateLiteral and
    result = templateConstantVal(exp.(TemplateLiteral))
  )
}

string regexpPattern(Expr exp)
{
  result = stringConstantVal(exp)
}

predicate isStringConstantExpr(Expr exp)
{
  exp instanceof ConstantString or
  (
    // const x = "foo";
    // new RegExp(x);
    //            ^--
    exp instanceof VarUse and
    not exists(Assignment assignment |
      assignment.getTarget().(VarUse).getSsaVariable() = exp.(VarUse).getSsaVariable()
    ) and
    isStringConstantExpr(
      exp.(VarUse).getVariable().getAnAssignedExpr()
    )
  ) or
  (
    exp instanceof AddExpr and
    isStringConstantExpr(exp.(AddExpr).getLeftOperand()) and
    isStringConstantExpr(exp.(AddExpr).getRightOperand())
  ) or
  (
    // /regexp/.source
    exp instanceof PropAccess and
    exp.(PropAccess).getPropertyName() = "source" and
    exists(Expr base |
      exp.(PropAccess).accesses(base, "source") and
      base.analyze().getAType() = TTRegExp()
    )
  ) or
  (
    // `${some}${format}`
    exp instanceof TemplateLiteral and
    (
      forall(Expr elem |
        elem = exp.(TemplateLiteral).getAnElement() |
        isStringConstantExpr(elem)
      )
    )
  )
}

// Given an expression which is interpreted as a
// RegExp, get the flags which are associated with this
// use (if any)
string companionFlags(Expr exp)
{
  (
    exists(
      NewExpr nexp |
        nexp = exp.getParentExpr() and
        (
          (nexp.getNumArgument() = 1 and result = "") or
          (result = stringConstantVal(nexp.getArgument(1)))
        )
    )
  ) or
  (
    exp instanceof RegExpLiteral and
    (
      result = exp.(RegExpLiteral).getFlags()
    )
  ) or
  (
    exists(
      MethodCallExpr mce |
      mce.getArgument(0) = exp and
      (
        (
          mce.getMethodName() = "search" and
          result = ""
        ) or
        (
          mce.getMethodName() = "match" and
          result = ""
        ) or
        (
          mce.getMethodName() = "matchAll" and
          result = "g"
        )
      )
    )
  )
}

// Given an expression which is interpreted as a regexp,
// return a string describing how that use happens
//
// Possible return vals:
// RegExpLiteral
// NewRegExp
// SearchCall
// MatchCall
// MatchAllCall
string callType(Expr exp)
{
  (
    exp instanceof RegExpLiteral and
      result = "RegExpLiteral"
  ) or
  (
    exists(
      NewExpr nexp |
      exp = nexp.getArgument(0)
    ) and
    result = "NewRegExp"
  ) or
  (
    // this is a result of some coercion to regexp
    exp.analyze().getAType() = TTString() and
    exists(
      MethodCallExpr mce |
      mce.getArgument(0) = exp and
      (
        (
          mce.getMethodName() = "search" and
          result = "SearchCall"
        ) or
        (
          mce.getMethodName() = "match" and
          result = "MatchCall"
        ) or
        (
          mce.getMethodName() = "matchAll" and
          result = "MatchAllCall"
        )
      )
    )
  )
}

from Expr exp
where
  isInterpretedAsRegExp2(exp.flow())
select
  // which file had the regexp
    exp.getLocation().getFile() as file_path
  // where in the file we found the regexp
  , exp.getLocation().getStartColumn() as start_col
  , exp.getLocation().getEndColumn() as end_col
  , exp.getLocation().getStartLine() as start_line
  , exp.getLocation().getEndLine() as end_line
  // use constant-folding to do a best-guess extraction
  // of the regexp literal
  , regexpPattern(exp) as pattern
  // flags found in this regexp
  , companionFlags(exp) as flags
  // what type of use was this
  , callType(exp) as call_type
