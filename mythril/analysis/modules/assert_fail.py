from z3 import *
from mythril.analysis import solver
from mythril.analysis.ops import *
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
import re
import logging

def execute(statespace):
    logging.debug("Executing module: ASSERT FAILS")
    issues = []

    for k in statespace.nodes:
        node = statespace.nodes[k]

        for instruction in node.instruction_list:
            
            if (instruction['opcode'] == "INVALID"):
                try:
                    model = solver.get_model(node.constraints)
                    issue = Issue(node.module_name, node.function_name, instruction['address'], "Assert Fail", "Warning")
                    issue.description = "A possible assert failure exists in the function " + node.function_name
                    issues.append(issue)

                    for d in model.decls():
                        print("[ASSERT_FAIL] model: %s = 0x%x" % (d.name(), model[d].as_long()))

                except UnsatError:
                    logging.debug("Couldn't find constraints to reach this invalid")

    return issues
