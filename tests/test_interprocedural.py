import pytest
from testutils import get_co, get_bytecode

from junkhacker import BytecodeObject
from junkhacker.bytecode.utils import show_bytecode
from junkhacker.bytecode.decl import Declaration
import junkhacker.utils.log as logutils
from junkhacker.utils.log import logger
logutils.enableLogger(to_file='./junkhacker.log.py')

from junkhacker.analysis import ControlFlow, BasicBlock

from graphviz import Digraph

import os
import pygraphviz as pgv

def test_interprocedural1():
  """
  Record what function is being called and what arguments are tainted, in call_function
  """
  f = open("files_to_test_against/simple_interprocedural1.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('Declarations are')
  logger.debug(bytecode_object.declarations)

  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)

  # We can save the cflow for each decl
  all_the_decls = {}

  # First loop gets all of the cflow objects for each decl
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters are')
      logger.debug(decl.formal_parameters)
      for param in decl.formal_parameters:
        if param != 'self':
          logger.debug("Going to say %s is tainted", param)

    logger.debug('dir(decl) is')
    logger.debug(dir(decl))
    cflow = ControlFlow(decl)

    all_the_decls[decl] = cflow

  # Now we can pass every cflow object to every decl
  for decl in bytecode_object.declarations:
    cflow = all_the_decls[decl]
    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    logger.debug('Now starting taint propagation')

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)


  logger.debug("All the decls dict is %s", all_the_decls)
  with open("junkhackee.log.py") as log_file:
    logs = log_file.read()
    key_string = "The function inter_procedural is called elsewhere in the code!"
    assert logs.count(key_string) == 1

    # interprocedural_log = "The function inter_procedural is being called with the following tainted args: set(['argument'])"
    interprocedural_log = "The function inter_procedural is being called with the following tainted args: set(['default', 'argument'])"
    assert logs.count(interprocedural_log) == 1

    # This is more Part 5 (return value taint_propagation)
    # With inlining we only return the root's current_interpreter, we don't want that interpreter. This is the child's interpeter that we want:
    # what_we_want = "BasicBlockInterpreter(\n\tstack=['argument']\n\tcalled_functions=[]\n\tenvironment={}\n\ttainted=set(['request', 'argument'])"
    # assert logs.count(what_we_want) == 2





def test_interprocedural2():
  """
      Write a taint_permutation wrapper that records function summaries
                                   Store where? The Declaration object?
  """
  f = open("files_to_test_against/simple_interprocedural2.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('Declarations are')
  logger.debug(bytecode_object.declarations)

  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)

  # We can save the cflow for each decl
  all_the_decls = {}

  # First loop gets all of the cflow objects for each decl
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters are')
      logger.debug(decl.formal_parameters)
      for param in decl.formal_parameters:
        if param != 'self':
          logger.debug("Going to say %s is tainted", param)

    logger.debug('dir(decl) is')
    logger.debug(dir(decl))
    cflow = ControlFlow(decl)

    all_the_decls[decl] = cflow

  # Now we can pass every cflow object to every decl
  for decl in bytecode_object.declarations:
    cflow = all_the_decls[decl]
    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    logger.debug('Now starting taint propagation')

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      for param in decl.formal_parameters:
        logger.debug("formal_param is %s", param)
        one_at_a_time = set()
        if param != 'self':
          one_at_a_time.add(param)
        logger.debug('one_at_a_time is %s', one_at_a_time)
        cflow.taint_propagation(cflow.root, decl, tainted=one_at_a_time, stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
        if decl.pretty_summary:
          logger.error(decl.formal_parameters)
          logger.error(decl.pretty_summary)
          logger.error(decl.one_param_summary)
          decl.all_params_summary[param] = decl.one_param_summary
          logger.error("Here it is :)")
          logger.error(decl.all_params_summary)

          # raise
      # cflow.taint_propagation(cflow.root, decl, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
      # if decl.pretty_summary:
      #   logger.error(decl.formal_parameters)
      #   logger.error(decl.pretty_summary)
      #   raise
    else:
      cflow.taint_propagation(cflow.root, current_decl=None, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)


  logger.debug("All the decls dict is %s", all_the_decls)
  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()
    key_string = "The function inter_procedural is called elsewhere in the code!"
    assert logs.count(key_string) > 0

    # It's 6 for some reason, the first time after you change something
    interprocedural_log = "The function inter_procedural is being called with the following tainted args"
    assert logs.count(interprocedural_log) == 10
    interprocedural_log = "The function inter_procedural is being called with the following tainted args: set(['default', 'other', 'argument'])"
    assert logs.count(interprocedural_log) == 10

    # This is more Part 5 (return value taint_propagation)
    # With inlining we only return the root's current_interpreter, we don't want that interpreter. This is the child's interpeter that we want:
    # what_we_want = "BasicBlockInterpreter(\n\tstack=['argument']\n\tcalled_functions=[]\n\tenvironment={}\n\ttainted=set(['request', 'argument'])"
    # assert logs.count(what_we_want) == 2


def test_interprocedural3():
  """
  Match the vuln_summary of what's being called with the tainted_args of what's calling it
  """
  f = open("files_to_test_against/simple_interprocedural3.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('Declarations are')
  logger.debug(bytecode_object.declarations)

  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)

  # We can save the cflow for each decl
  all_the_decls = {}

  # First loop gets all of the cflow objects for each decl
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters are')
      logger.debug(decl.formal_parameters)
      for param in decl.formal_parameters:
        if param != 'self':
          logger.debug("Going to say %s is tainted", param)

    logger.debug('dir(decl) is')
    logger.debug(dir(decl))
    cflow = ControlFlow(decl)

    all_the_decls[decl] = cflow

  # Now we can pass every cflow object to every decl
  for decl in bytecode_object.declarations:
    cflow = all_the_decls[decl]
    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    logger.debug('Now starting taint propagation')

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      for param in decl.formal_parameters:
        logger.debug("formal_param is %s", param)
        one_at_a_time = set()
        if param != 'self':
          one_at_a_time.add(param)
        logger.debug('one_at_a_time is %s', one_at_a_time)
        cflow.taint_propagation(cflow.root, decl, tainted=one_at_a_time, stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
        if decl.pretty_summary:
          logger.error(decl.formal_parameters)
          logger.error(decl.pretty_summary)
          logger.error(decl.one_param_summary)
          decl.all_params_summary[param] = decl.one_param_summary
          logger.error("Here it is :)")
          logger.error(decl.all_params_summary)

        if decl.vuln_summary:
          logger.error("ONE TIME ONLY!")
          decl.all_params_vuln_summary[param] = decl.vuln_summary
          # We clean the slate for the next param
          decl.vuln_summary = []
          decl.inter_vuln_summary = []

          # raise
      # cflow.taint_propagation(cflow.root, decl, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
      # if decl.pretty_summary:
      #   logger.error(decl.formal_parameters)
      #   logger.error(decl.pretty_summary)
      #   raise
    else:
      cflow.taint_propagation(cflow.root, current_decl=None, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)


  logger.debug("All the decls dict is %s", all_the_decls)
  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()
    key_string = "The function inter_procedural is called elsewhere in the code!"
    assert logs.count(key_string) == 1

    inter_proof = "Mother fucker, we just did interprocedural taint-tracking. argument is in set(['default', 'other', 'argument'])"
    assert logs.count(key_string) == 1






def test_interprocedural4():
  """
  Determine taint of a return value with a summary of the callee
  """
  f = open("files_to_test_against/simple_interprocedural4.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('Declarations are')
  logger.debug(bytecode_object.declarations)

  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)

  # We can save the cflow for each decl
  all_the_decls = {}

  # First loop gets all of the cflow objects for each decl
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters are')
      logger.debug(decl.formal_parameters)
      for param in decl.formal_parameters:
        if param != 'self':
          logger.debug("Going to say %s is tainted", param)

    logger.debug('dir(decl) is')
    logger.debug(dir(decl))
    cflow = ControlFlow(decl)

    all_the_decls[decl] = cflow

  logger.debug("Decls are in this order %s", reversed(bytecode_object.declarations))
  logger.debug("Decls are in this order type(%s)", type(bytecode_object.declarations))

  x = 0
  # Now we can pass every cflow object to every decl
  for decl in reversed(bytecode_object.declarations):
    cflow = all_the_decls[decl]
    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    logger.debug('Hmm so cflow.exit_node is %s', cflow.exit_node)
    logger.debug('Hmm so cflow.graph.in_edges(cflow.exit_node) is %s', cflow.graph.in_edges(cflow.exit_node))
    for in_edge in cflow.graph.in_edges(cflow.exit_node):
      logger.debug("Node in_edge.source.data is %s", in_edge.source.data)
      logger.debug("Node in_edge.source.data.length is %s", in_edge.source.data.length)
      logger.debug("Node in_edge.source.data.bytecode_slice is %s", in_edge.source.data.bytecode_slice)
      logger.debug("Node in_edge.source.data.end_target is %s", in_edge.source.data.end_target)
      in_edge.source.data.has_ret_value = True

    logger.debug('Now starting taint propagation')

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      for param in decl.formal_parameters:
        logger.debug("formal_param is %s", param)
        one_at_a_time = set()
        if param != 'self':
          one_at_a_time.add(param)
        logger.debug('one_at_a_time is %s', one_at_a_time)
        cflow.taint_propagation(cflow.root, decl, tainted=one_at_a_time, stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
        if decl.pretty_summary:
          logger.error(decl.formal_parameters)
          logger.error(decl.pretty_summary)
          logger.error(decl.one_param_summary)
          decl.all_params_summary[param] = decl.one_param_summary
          logger.error("Here it is :)")
          logger.error(decl.all_params_summary)

        if decl.vuln_summary:
          logger.error("ONE TIME ONLY!")
          decl.all_params_vuln_summary[param] = decl.vuln_summary
          # We clean the slate for the next param
          decl.vuln_summary = []
          decl.inter_vuln_summary = []

        if decl.returns_tainted:
          decl.all_params_returns_tainted[param] = True
          logger.debug("BEFORE")
          decl.returns_tainted = False

        f = open('VIEWS'+str(x)+'.dot', 'w')
        f.write(cflow.graph.to_dot())
        f.close()

        G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
        G.layout()
        G.draw('VIEWS'+str(x)+'.png')
        x = x+1

          # raise
      # cflow.taint_propagation(cflow.root, decl, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
      # if decl.pretty_summary:
      #   logger.error(decl.formal_parameters)
      #   logger.error(decl.pretty_summary)
      #   raise
    else:
      cflow.taint_propagation(cflow.root, current_decl=None, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True)
      f = open('VIEWS'+str(x)+'.dot', 'w')
      f.write(cflow.graph.to_dot())
      f.close()

      G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
      G.layout()
      G.draw('VIEWS'+str(x)+'.png')
      x = x+1


  logger.debug("All the decls dict is %s", all_the_decls)
  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()
    key_string = "The function inter_procedural is called elsewhere in the code!"
    assert logs.count(key_string) == 1

    inter_proof = "The sink self.redirect has tainted argument ret_val"
    assert logs.count(key_string) == 1
