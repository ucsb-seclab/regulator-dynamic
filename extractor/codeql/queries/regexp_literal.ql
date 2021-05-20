/**
 * @kind path-problem
 * @problem.severity error
 */

import javascript

from RegExpLiteral expr
select
    expr.getFile().getAbsolutePath() as file_path
    , expr.getLocation().getStartColumn() as start_col
    , expr.getLocation().getEndColumn() as end_col
    , expr.getLocation().getStartLine() as start_line
    , expr.getLocation().getEndLine() as end_line  
    , expr.getRoot().getRawValue() as pattern
    , expr.getFlags() as flags
