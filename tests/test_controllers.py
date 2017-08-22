import pytest
from testutils import get_co, get_bytecode

from junkhacker import BytecodeObject
from junkhacker.analysis import ControlFlow, BasicBlock
from junkhacker.analysis.graph.traversals import bfs_set_buddies
from junkhacker.bytecode.decl import Declaration
from junkhacker.bytecode.utils import show_bytecode
from junkhacker.utils.log import logger
import junkhacker.utils.log as logutils

from graphviz import Digraph
import os
import pygraphviz as pgv
from unittest import TestCase

logutils.enableLogger(to_file='./junkhacker.log.py')

def test_beep():
  f = open("files_to_test_against/beep.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
      logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)



    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)



    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0





























def test_slice():
  """

  """
  f = open("files_to_test_against/slice.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
      logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)
    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    key_string0 = "slicey is enzo[*const_1:4]"
    assert key_string0 in logs
    assert logs.count(key_string0) == 1

    key_string1 = "slicey is enzo[*const_8:4]"
    assert key_string1 in logs
    assert logs.count(key_string1) == 1

    key_string2 = "slicey is enzo[0:*const_-1]"
    assert key_string2 in logs
    assert logs.count(key_string2) == 1

    key_string3 = "slicey is enzo[0:*const_1]"
    assert key_string3 in logs
    assert logs.count(key_string3) == 1

    key_string4 = "slicey is enzo[*const_3:*const_1]"
    assert key_string4 in logs
    assert logs.count(key_string4) == 1

    key_string5 = "'den5zel': 'SUBSCR(enzo, *const_8:*const_1:*const_2)'"
    assert key_string5 in logs
    assert logs.count(key_string5) == 6

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0






def test_tada():
  """
  def __init__(self, enzo=None, kevin=None):
    self.enzo = enzo
    self.kevin = kevin
    self.denzel = ' '.join(map(lambda x: x[0].upper() + x[1:], enzo[:-len('@foo.com')].split('.')))
  """
  f = open("files_to_test_against/tada.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
      logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)
    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    # It doesn't crash, but I'm not doing slice taints or inter-procedural stuff yet
    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0













def test_change_your_life():
  f = open("files_to_test_against/change_your_life.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
      logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)



    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)



    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()
    key_string = "The sink self.redirect has tainted argument next_url"
    assert key_string in logs
    assert logs.count(key_string) == 72










def test_a_huge_file():
  f = open("/Users/kevinhock/Documents/david/equip-master/tests/files_to_test_against/admin.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    # if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
    #   logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)



    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)



    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    key_string = "The sink self.redirect has tainted argument next_url"
    assert key_string in logs
    assert logs.count(key_string) == 72

    key_string = "Giving up, too many recursions"
    assert logs.count(key_string) == 188 + 7

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0




def test_a_seq():
  f = open("files_to_test_against/seq.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    # if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
    #   logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)



    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)



    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    key_string0 = "return value of \"('hubba.forty', ['is_old'], {'*const_gum': 'gum', '*const_very': 'water'})\" index 0 is being stored into birthday"
    assert logs.count(key_string0) == 1

    key_string1 = "return value of \"('hubba.forty', ['is_old'], {'*const_gum': 'gum', '*const_very': 'water'})\" index 1 is being stored into thomas"
    assert logs.count(key_string1) == 1

    key_string2 = "return value of \"('hubba.forty', ['is_old'], {'*const_gum': 'gum', '*const_very': 'water'})\" index 2 is being stored into ptacek"
    assert logs.count(key_string2) == 1

    too_many_recursions = "Giving up, too many recursions"
    assert logs.count(too_many_recursions) == 0

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0




def test_issueTree():
  """
  Test out huge mother fucker against fixed dominator code.
  This means both
      the buddy system worked.
      the dominators fix worked.
  """
  f = open("files_to_test_against/issue#2.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('Declarations are')
  logger.debug(bytecode_object.declarations)

  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)

  # We can save the cflow for each decl
  all_the_decls = {}

  # First loop gets all of the cflow objects for each decl
  for decl in bytecode_object.declarations:
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

    graph = cflow.graph

    # Start new code
    logger.debug("Uh what, # of nodes is %s", len(graph.nodes))
    logger.debug("Here they are %s", graph.nodes)
    # Access first element of the set
    for node in graph.nodes:
      if node.kind == 'ENTRY':
        # We just want to run this on the root
        bfs_set_buddies(graph, node)
        # raise
        break
    # End new code

    for node in graph.nodes:
      logger.debug("Bing %s is %s", type(node), node)
      predecessors = graph.in_edges(node)
      if len(predecessors) >= 2:
        logger.debug("predecessors for %s are %s", node, predecessors)

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
        cflow.taint_propagation(cflow.root, decl, tainted=one_at_a_time, stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True, stack_of_buddies=[])
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
    else:
      cflow.taint_propagation(cflow.root, current_decl=None, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True, stack_of_buddies=[])
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
    first_key_string = "So current_bloc.succ == stack_of_buddies[-1]"
    assert logs.count(first_key_string) == 31

    last_key_string = "Uh oh spaghettios"
    assert logs.count(last_key_string) == 2





def test_issue3():
  """
  Fix the Exception KeyError e.g.
    dominators.py::build(91) - Exception KeyError(Node56(kind='', uuids=set([]), buddy=None, data=BasicBlock(1797->1799) has_ret_val is False),)
    Traceback (most recent call last):
      File "/Users/kevinhock/Documents/collabs/junkhacker/junkhacker/analysis/graph/dominators.py", line 82, in build
        self.__build_dominators(graph, entry, post_dom=False)
      File "/Users/kevinhock/Documents/collabs/junkhacker/junkhacker/analysis/graph/dominators.py", line 163, in __build_dominators
        new_idom = intersec(p, new_idom)
      File "/Users/kevinhock/Documents/collabs/junkhacker/junkhacker/analysis/graph/dominators.py", line 129, in intersec
        po_finger2 = post_order_number[finger2]
    KeyError: Node56(kind='', uuids=set([]), buddy=None, data=BasicBlock(1797->1799) has_ret_val is False)
  """
  # f = open("files_to_test_against/issue#3.py")
  # f = open("files_to_test_against/issue#2b_skinny.py")
  # f = open("files_to_test_against/issue#2c.py")
  f = open("files_to_test_against/issue#2.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    # if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
    #   logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)

    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    # if decl.kind == Declaration.METHOD:
    #   cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    # else:
    #   cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    # key_string0 = "return value of \"('hubba.forty', ['is_old'], {'*const_gum': 'gum', '*const_very': 'water'})\" index 0 is being stored into birthday"
    # assert key_string0 in logs
    # assert logs.count(key_string0) == 1

    # key_string0 = "return value of \"('hubba.forty', ['is_old'], {'*const_gum': 'gum', '*const_very': 'water'})\" index 1 is being stored into thomas"
    # assert key_string0 in logs
    # assert logs.count(key_string0) == 1


    # key_string0 = "kwargs is probably symbolic so we're gonna ignore it"
    # assert logs.count(key_string0) == 1

    # too_many_recursions = "Giving up, too many recursions"
    # assert logs.count(too_many_recursions) == 0
    # assert logs.count(too_many_recursions) == 311

    # there_was_an_exception = "Exception"
    # assert logs.count(there_was_an_exception) == 0

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0



def test_a_2nd_huge_file():
  f = open("/Users/kevinhock/Documents/david/equip-master/tests/files_to_test_against/login.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    # if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
    #   logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)



    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)



    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    key_string = "The sink self.redirect has tainted argument next_url"
    assert key_string in logs
    assert logs.count(key_string) == 1

    key_string = "Giving up, too many recursions"
    assert logs.count(key_string) == 211

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0




def test_get_money():
  # f = open("files_to_test_against/get_money.py")
  f = open("/Users/kevinhock/Documents/david/equip-master/tests/files_to_test_against/get_money.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
      logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)



    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)



    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')


    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()
    key_string = "Giving up, too many recursions"
    assert logs.count(key_string) == 188

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0











































def test_small_get_money():
  f = open("files_to_test_against/small_get_money.py")
  source = f.read()

  logger.debug('source is')
  logger.debug(source)

  bytecode_object = BytecodeObject('<string>')
  compiled_code = get_co(source)
  bytecode_object.parse_code(compiled_code)

  logger.debug('ghi declarations are')
  logger.debug(bytecode_object.declarations)
  # logger.debug('ghi dir(bytecode_object) is')
  # logger.debug(dir(bytecode_object))
  logger.debug('bytecode_object.main_module is')
  logger.debug(bytecode_object.main_module)
  for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
    logger.debug('imp_stmt is')
    logger.debug(imp_stmt)
    if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
      logger.debug("EMERGENCY")
  x = 0
  for decl in bytecode_object.declarations:
    # logger.debug('decl.formal_parameters is')
    # logger.debug(decl.formal_parameters)
    logger.debug('decl.kind is')
    logger.debug(decl.kind)
    if decl.kind == Declaration.METHOD:
      logger.debug('decl.formal_parameters is')
      logger.debug(decl.formal_parameters)
    logger.debug('dir(decl) is')
    logger.debug(dir(decl))

    cflow = ControlFlow(decl)

    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    # vv Not sure if valid any more vv
    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    # ^^ Not sure if valid any more ^^
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()

    # There are 6 different paths through the program, line 17 has a lot of things going on at once, so we test what's on the stack at that line each time
    stack_1 = [{'*const_yotel': 'yotel'}, [], '*const_wallet']
    stack_2 = [{'*const_wallet': [{'*const_fade': 'work.fade', '*const_sade': 'work.sade', '*const_started': 'return value of "(\'work.started.strftime\', [\'*const_%Y-%m-%d %H:%M:%S UTC\'], {})"'}], '*const_yotel': 'yotel'}, [{'*const_fade': 'work.fade', '*const_sade': 'work.sade', '*const_started': 'return value of "(\'work.started.strftime\', [\'*const_%Y-%m-%d %H:%M:%S UTC\'], {})"'}], '*const_wallet']
    stack_3 = [{'*const_wallet': [{'*const_fade': 'work.fade', '*const_sade': 'work.sade', '*const_started': '*const_None'}, {'*const_fade': 'work.fade', '*const_sade': 'work.sade', '*const_started': '*const_None'}], '*const_yotel': 'yotel'}, [{'*const_fade': 'work.fade', '*const_sade': 'work.sade', '*const_started': '*const_None'}, {'*const_fade': 'work.fade', '*const_sade': 'work.sade', '*const_started': '*const_None'}], '*const_wallet']

    key_string_1 = str(stack_1)
    key_string_2 = str(stack_2)
    key_string_3 = str(stack_3)

    assert logs.count(key_string_1) > 0
    assert logs.count(key_string_2) > 0
    assert logs.count(key_string_3) > 0

    there_was_an_error = "Traceback"
    assert logs.count(there_was_an_error) == 0











class TestInterpreter(TestCase):
    def test_tainted_by(self):
      # Just a very simple file
      self._run_file('test_tainted_by1')

      def check_interpreter(self, interpreter):
          if interpreter.tainted_by != {}:
            logger.error("Hmm so interpreter.tainted_by is %s", interpreter.tainted_by)
            assert interpreter.tainted_by['c.tboo'] == ['strange']

      self.check_interpreter = check_interpreter

    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)

    def _run_file(self, file):
      f = open("files_to_test_against/" + file + ".py")
      source = f.read()

      bytecode_object = BytecodeObject('<string>')
      compiled_code = get_co(source)
      bytecode_object.parse_code(compiled_code)

      logger.debug('Declarations are')
      logger.debug(bytecode_object.declarations)

      logger.debug('bytecode_object.main_module is')
      logger.debug(bytecode_object.main_module)

      # We can save the cflow for each decl
      all_the_decls = {}

      # First loop gets all of the cflow objects for each decl
      for decl in bytecode_object.declarations:
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

      # Now we can pass every cflow object to every decl
      for decl in reversed(bytecode_object.declarations):
        cflow = all_the_decls[decl]
        # Print BasicBlocks
        logger.debug("Blocks in CFG are: ")
        for b in cflow.blocks:
          logger.debug(b)

        logger.debug('dominators.frontier is')
        logger.debug(cflow.dominators.frontier)

        graph = cflow.graph

        # Start buddy code
        logger.debug("Uh what, # of nodes is %s", len(graph.nodes))
        logger.debug("IN HERE Here they are %s", graph.nodes)
        # Access first element of the set
        for node in graph.nodes:
          if node.kind == 'ENTRY':
            # We just want to run this on the root
            bfs_set_buddies(graph, node)
            # raise
            break
        # End buddy code

        score = []
        # tainted_by = {'request':['request']}
        tainted_by = {}

        if decl.kind == Declaration.METHOD:
            # We aren't doing "one_at_a_time yet", nor "other_decls" (inter)
            # cflow.taint_propagation(cflow.root, decl, tainted=one_at_a_time, stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=all_the_decls, interprocedural_mode=True, stack_of_buddies=[])
            current_interpreter = cflow.taint_propagation(cflow.root, decl, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=None, interprocedural_mode=False, stack_of_buddies=[], score=score, tainted_by=tainted_by)
        else:
            current_interpreter = cflow.taint_propagation(cflow.root, current_decl=None, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', other_decls=None, interprocedural_mode=False, stack_of_buddies=[], score=score, tainted_by=tainted_by)

        self.check_interpreter(current_interpreter)












class TestBuddySystem(TestCase):
    def test_buddy_system_on_or(self):
      """
            if honey or not booboo(redirect_url):
                self.redirect(c.next)
            return self.redirect(c.tboo)

            A
            | \
            B->C
            | /
            D
      """
      self._run_file("test_buddy_system_on_or")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 2
        assert logs.count("Okay so (0->59) has the buddy (92->104)") == 1
        assert logs.count("Okay so (60->72) has the buddy (92->104)") == 1


    def test_buddy_system_on_and(self):
      """
            if honey and not booboo(redirect_url):
                self.redirect(c.next)
            return self.redirect(c.tboo)

            A
            |\
            | B
            |/ \
            D<--C
      """
      self._run_file("test_buddy_system_on_and")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 2
        assert logs.count("Okay so (0->59) has the buddy (92->104)") == 1
        assert logs.count("Okay so (60->72) has the buddy (92->104)") == 1


    def test_buddy_system_on_and_N_times(self):
      """
            if honey and not booboo(redirect_url):
                self.redirect(c.next)
            return self.redirect(c.tboo)

            A
            |\
            | B
            |/ \
            |   C
            | /  \
            |/    D
            |    / \
            |   /   \
            |  /     \
            | /       \
            |/         \
            |           \
            F<-----------E
      """
      self._run_file("test_buddy_system_on_and_N_times")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 4
        assert logs.count("Okay so (0->59) has the buddy (110->122)") == 1
        assert logs.count("Okay so (60->72) has the buddy (110->122)") == 1
        assert logs.count("Okay so (73->81) has the buddy (110->122)") == 1
        assert logs.count("Okay so (82->90) has the buddy (110->122)") == 1


    def test_buddy_system_on_or_N_times(self):
      """
            if abby or not something(1) or c.tboo or c.next:
                self.redirect(c.next)
            return self.redirect(c.tboo)

                   A
                  / \
                 B-->\
                /     \
               C------>\
              /         \
             D---------->\
            /             \
           F<--------------E
      """
      self._run_file("test_buddy_system_on_or_N_times")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 4
        assert logs.count("Okay so (0->59) has the buddy (110->122)") == 1
        assert logs.count("Okay so (60->72) has the buddy (110->122)") == 1
        assert logs.count("Okay so (73->81) has the buddy (110->122)") == 1
        assert logs.count("Okay so (82->90) has the buddy (110->122)") == 1


    def test_path_explosion1(self):
      """
          def picky(self):
              c.next = request.params.get('next')
              c.tboo = request.params.get('tboo')

              if 'hi' == c.next:
                  print 'hi'
              else:
                  print 'goodbye'

              # Does this have 1 thread or 2?
              return self.redirect(c.tboo)

              2(  0)          LOAD_GLOBAL(116) ('request')
              2(  3)            LOAD_ATTR(106) ('params')
              2(  6)            LOAD_ATTR(106) ('get')
              2(  9)           LOAD_CONST(100) ('next')
              2( 12)        CALL_FUNCTION(131) (1)
              2( 15)          LOAD_GLOBAL(116) ('c')
              2( 18)           STORE_ATTR( 95) ('next')
              3( 21)          LOAD_GLOBAL(116) ('request')
              3( 24)            LOAD_ATTR(106) ('params')
              3( 27)            LOAD_ATTR(106) ('get')
              3( 30)           LOAD_CONST(100) ('tboo')
              3( 33)        CALL_FUNCTION(131) (1)
              3( 36)          LOAD_GLOBAL(116) ('c')
              3( 39)           STORE_ATTR( 95) ('tboo')
              5( 42)           LOAD_CONST(100) ('hi')
              5( 45)          LOAD_GLOBAL(116) ('c')
              5( 48)            LOAD_ATTR(106) ('next')
              5( 51)           COMPARE_OP(107) ('==')
              5( 54)    POP_JUMP_IF_FALSE(114) (65) -------------> ( 65)

              6( 57)           LOAD_CONST(100) ('hi')
              6( 60)           PRINT_ITEM( 71)
              6( 61)        PRINT_NEWLINE( 72)
              6( 62)         JUMP_FORWARD(110) (5) -------------> ( 70)

              8( 65)           LOAD_CONST(100) ('goodbye')
              8( 68)           PRINT_ITEM( 71)
              8( 69)        PRINT_NEWLINE( 72)

             11( 70)            LOAD_FAST(124) ('self')
             11( 73)            LOAD_ATTR(106) ('redirect')
             11( 76)          LOAD_GLOBAL(116) ('c')
             11( 79)            LOAD_ATTR(106) ('tboo')
             11( 82)        CALL_FUNCTION(131) (1)


             (0-56) is only BB with 2 kids
             (57-64) .5
             (65-69) .5
             (70-82) GET THE BUDDIES
      """
      self._run_file("test_path_explosion1")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 1
        assert logs.count("Okay so (0->56) has the buddy (70->82)") == 1


    def test_path_explosion2(self):
      """

      """
      self._run_file("test_path_explosion2")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 1
        assert logs.count("Okay so (0->56) has the buddy (65->77)") == 1


    def test_path_explosion3(self):
      """

      """
      self._run_file("test_path_explosion3")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 1
        assert logs.count("Okay so (0->62) has the buddy (94->106)") == 1


    def test_mix_and_or_dont_have_dupes(self):
      """
            if abby or not something(1) and c.tboo or c.next:
                self.redirect(c.next)
            return self.redirect(c.tboo)
            (0, 60), (60, 73), (73, 82), (82, 91), (91, 110), (110, 123)

            A
            2(  0)          LOAD_GLOBAL(116) ('request')
            2(  3)            LOAD_ATTR(106) ('params')
            2(  6)            LOAD_ATTR(106) ('get')
            2(  9)           LOAD_CONST(100) ('next')
            2( 12)        CALL_FUNCTION(131) (1)
            2( 15)          LOAD_GLOBAL(116) ('c')
            2( 18)           STORE_ATTR( 95) ('next')
            3( 21)          LOAD_GLOBAL(116) ('request')
            3( 24)            LOAD_ATTR(106) ('params')
            3( 27)            LOAD_ATTR(106) ('get')
            3( 30)           LOAD_CONST(100) ('tboo')
            3( 33)        CALL_FUNCTION(131) (1)
            3( 36)          LOAD_GLOBAL(116) ('c')
            3( 39)           STORE_ATTR( 95) ('tboo')
            5( 42)            LOAD_FAST(124) ('abby')
            5( 45)            LOAD_ATTR(106) ('pie')
            5( 48)        CALL_FUNCTION(131) (0)
            5( 51)           STORE_FAST(125) ('abby')
            6( 54)            LOAD_FAST(124) ('abby')
            6( 57)     POP_JUMP_IF_TRUE(115) (91) -------------> ( 91)

            B
            6( 60)          LOAD_GLOBAL(116) ('something')
            6( 63)           LOAD_CONST(100) (1)
            6( 66)        CALL_FUNCTION(131) (1)
            6( 69)            UNARY_NOT( 12)
            6( 70)    POP_JUMP_IF_FALSE(114) (82) -------------> ( 82)

            C
            6( 73)          LOAD_GLOBAL(116) ('c')
            6( 76)            LOAD_ATTR(106) ('tboo')
            6( 79)     POP_JUMP_IF_TRUE(115) (91) -------------> ( 91)

            D
            6( 82)          LOAD_GLOBAL(116) ('c')
            6( 85)            LOAD_ATTR(106) ('next')
            6( 88)    POP_JUMP_IF_FALSE(114) (110) -------------> (110)


            E
            7( 91)            LOAD_FAST(124) ('self')
            7( 94)            LOAD_ATTR(106) ('redirect')
            7( 97)          LOAD_GLOBAL(116) ('c')
            7(100)            LOAD_ATTR(106) ('next')
            7(103)        CALL_FUNCTION(131) (1)
            7(106)              POP_TOP(  1)
            7(107)         JUMP_FORWARD(110) (0) -------------> (110)

            F
            9(110)            LOAD_FAST(124) ('self')
            9(113)            LOAD_ATTR(106) ('redirect')
            9(116)          LOAD_GLOBAL(116) ('c')
            9(119)            LOAD_ATTR(106) ('tboo')
            9(122)        CALL_FUNCTION(131) (1)
    A 0-59
    B 60-72
    C 73-81
    D 82-90
    E 91-109
    F 110-122

    AE
    AB
    EF
    BD
    BC
    F-END
    DE
    DF
    (C now has .5 of B and .25 of A) :thumbsup:
    CD
    CE
    (E now has .5 of D, .75 of A, .5 of B, .5 of C)
    EF
    (F now has 1.0 of D, .75 of A, .5 of B, .5 of C)
    F
    (D now has .375 of A, .75 of B, .5 of C)
    DE
    DF
    (E now has .9375 of A, .875 of B, .75 of C)
    EF
    (F now has 1.25 of A,  1.5 of B,  1.0 of C, .5 of D)

    THE PROBLEM I HAD
      When D splits nodes, they're compeletely new UUIDs, so we can't do that more than once.

                      A
                     / \
                    B   \
                   / \   \
                  C-->\-->\
                       D   \
                      / \   \
                     /   \   \
                    /     \   \
                   /       \___\
            F<------------------E

            Everyone's buddy (ABCD's) is still F, yet there are duplicates!

            Weird, something w/ the manager had -1->-1 as the buddy of everything :/
      """
      self._run_file("test_mix_and_or_dont_have_dupes")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 4
        assert logs.count("Okay so (0->59) has the buddy (110->122)") == 1
        assert logs.count("Okay so (60->72) has the buddy (110->122)") == 1
        assert logs.count("Okay so (73->81) has the buddy (110->122)") == 1
        assert logs.count("Okay so (82->90) has the buddy (110->122)") == 1


    def test_buddy_system_with_return(self):
      """
        Recognize that 82->92 is a return block.
          -> DONE via has_return_value
        Give all UUIDs to 92->106.

        def picky(self):
            infected = request.params.get('hey')
            ray = orange.grab.this('ray', None)
            # lenny = 't' if ray is not None else 'f'
            briscoe, law = And.order(orange.environ,
                orange.grab)
            if law and not briscoe:
                return guilty(law)
            self.redirect(infected)


        2(  0)          LOAD_GLOBAL(116) ('request')
        2(  3)            LOAD_ATTR(106) ('params')
        2(  6)            LOAD_ATTR(106) ('get')
        2(  9)           LOAD_CONST(100) ('hey')
        2( 12)        CALL_FUNCTION(131) (1)
        2( 15)           STORE_FAST(125) ('infected')
        3( 18)          LOAD_GLOBAL(116) ('orange')
        3( 21)            LOAD_ATTR(106) ('grab')
        3( 24)            LOAD_ATTR(106) ('this')
        3( 27)           LOAD_CONST(100) ('ray')
        3( 30)           LOAD_CONST(100) (None)
        3( 33)        CALL_FUNCTION(131) (2)
        3( 36)           STORE_FAST(125) ('ray')
        5( 39)          LOAD_GLOBAL(116) ('And')
        5( 42)            LOAD_ATTR(106) ('order')
        5( 45)          LOAD_GLOBAL(116) ('orange')
        5( 48)            LOAD_ATTR(106) ('environ')
        6( 51)          LOAD_GLOBAL(116) ('orange')
        6( 54)            LOAD_ATTR(106) ('grab')
        6( 57)        CALL_FUNCTION(131) (2)
        6( 60)      UNPACK_SEQUENCE( 92) (2)
        6( 63)           STORE_FAST(125) ('briscoe')
        6( 66)           STORE_FAST(125) ('law')
        7( 69)            LOAD_FAST(124) ('law')
        7( 72)    POP_JUMP_IF_FALSE(114) (92) -------------> ( 92)

        7( 75)            LOAD_FAST(124) ('briscoe')
        7( 78)            UNARY_NOT( 12)
        7( 79)    POP_JUMP_IF_FALSE(114) (92) -------------> ( 92)

        8( 82)          LOAD_GLOBAL(116) ('guilty')
        8( 85)            LOAD_FAST(124) ('law')
        8( 88)        CALL_FUNCTION(131) (1)
        8( 91)         RETURN_VALUE( 83)

        9( 92)            LOAD_FAST(124) ('self')
        9( 95)            LOAD_ATTR(106) ('redirect')
        9( 98)            LOAD_FAST(124) ('infected')
        9(101)        CALL_FUNCTION(131) (1)
        9(104)              POP_TOP(  1)
        9(105)           LOAD_CONST(100) (None)
      """
      self._run_file("test_buddy_system_with_return")
      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 2
        assert logs.count("Okay so (0->74) has the buddy (92->105)") == 1
        assert logs.count("Okay so (75->81) has the buddy (92->105)") == 1


    def test_buddy_system_with_for(self):
      """
        def picky(self):
            c.iced = iced.me()
            c.foo = c.iced.foo
            c.next = secure_get_next_url(request.params.get('next'))

            if len(c.foo) == 1:
                return self.redirect(c.next)
            else:
                c.star = c.iced.spring.id
                for h in c.foo:
                    bucks = h.spring.mocha.ran if h.spring.mocha else True
                    h.poland = water[bucks]
                return render('/dotdot')

          2(  0)          LOAD_GLOBAL(116) ('User')
          2(  3)            LOAD_ATTR(106) ('me')
          2(  6)        CALL_FUNCTION(131) (0)
          2(  9)          LOAD_GLOBAL(116) ('c')
          2( 12)           STORE_ATTR( 95) ('user')
          3( 15)          LOAD_GLOBAL(116) ('c')
          3( 18)            LOAD_ATTR(106) ('user')
          3( 21)            LOAD_ATTR(106) ('user_orgs')
          3( 24)          LOAD_GLOBAL(116) ('c')
          3( 27)           STORE_ATTR( 95) ('user_orgs')
          4( 30)          LOAD_GLOBAL(116) ('secure_get_next_url')
          4( 33)          LOAD_GLOBAL(116) ('request')
          4( 36)            LOAD_ATTR(106) ('params')
          4( 39)            LOAD_ATTR(106) ('get')
          4( 42)           LOAD_CONST(100) ('next')
          4( 45)        CALL_FUNCTION(131) (1)
          4( 48)          LOAD_GLOBAL(116) ('url')
          4( 51)           LOAD_CONST(100) ('Home')
          4( 54)        CALL_FUNCTION(131) (1)
          4( 57)        CALL_FUNCTION(131) (2)
          4( 60)          LOAD_GLOBAL(116) ('c')
          4( 63)           STORE_ATTR( 95) ('next')
          6( 66)          LOAD_GLOBAL(116) ('len')
          6( 69)          LOAD_GLOBAL(116) ('c')
          6( 72)            LOAD_ATTR(106) ('user_orgs')
          6( 75)        CALL_FUNCTION(131) (1)
          6( 78)           LOAD_CONST(100) (1)
          6( 81)           COMPARE_OP(107) ('==')
          6( 84)    POP_JUMP_IF_FALSE(114) (103) -------------> (103)

          7( 87)            LOAD_FAST(124) ('self')
          7( 90)            LOAD_ATTR(106) ('redirect')
          7( 93)          LOAD_GLOBAL(116) ('c')
          7( 96)            LOAD_ATTR(106) ('next')
          7( 99)        CALL_FUNCTION(131) (1)
          7(102)         RETURN_VALUE( 83)

          9(103)          LOAD_GLOBAL(116) ('c')
          9(106)            LOAD_ATTR(106) ('user')
          9(109)            LOAD_ATTR(106) ('org')
          9(112)            LOAD_ATTR(106) ('id')
          9(115)          LOAD_GLOBAL(116) ('c')
          9(118)           STORE_ATTR( 95) ('current_org_id')

         10(121)           SETUP_LOOP(120) (69) -------------> (193)

         10(124)          LOAD_GLOBAL(116) ('c')
         10(127)            LOAD_ATTR(106) ('user_orgs')
         10(130)             GET_ITER( 68)

         10(131)             FOR_ITER( 93) (58) -------------> (192)

         10(134)           STORE_FAST(125) ('u')
         11(137)            LOAD_FAST(124) ('u')
         11(140)            LOAD_ATTR(106) ('org')
         11(143)            LOAD_ATTR(106) ('subscription')
         11(146)    POP_JUMP_IF_FALSE(114) (164) -------------> (164)

         11(149)            LOAD_FAST(124) ('u')
         11(152)            LOAD_ATTR(106) ('org')
         11(155)            LOAD_ATTR(106) ('subscription')
         11(158)            LOAD_ATTR(106) ('billing_plan_id')
         11(161)         JUMP_FORWARD(110) (6) -------------> (170)

         11(164)          LOAD_GLOBAL(116) ('BillingPlan')
         11(167)            LOAD_ATTR(106) ('FREE')
         11(170)           STORE_FAST(125) ('plan_id')
         12(173)          LOAD_GLOBAL(116) ('BillingPlan')
         12(176)            LOAD_ATTR(106) ('NAMES')
         12(179)            LOAD_FAST(124) ('plan_id')
         12(182)        BINARY_SUBSCR( 25)
         12(183)            LOAD_FAST(124) ('u')
         12(186)           STORE_ATTR( 95) ('plan_name')
         12(189)        JUMP_ABSOLUTE(113) (131) -------------> (131)

         12(192)            POP_BLOCK( 87)

         13(193)          LOAD_GLOBAL(116) ('render')
         13(196)           LOAD_CONST(100) ('/landing/pick_org.mako')
         13(199)        CALL_FUNCTION(131) (1)
         13(202)         RETURN_VALUE( 83)
         13(203)           LOAD_CONST(100) (None)
      """
      self._run_file("test_buddy_system_with_for")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 1
        assert logs.count("Okay so (88->99) has the buddy (112->130)") == 1

    def test_buddy_system_with_multi_if(self):
      """
           A
           |\
           | \
           |  B
           | /
           C
           | \
           |  \
           |   D
           |  /
           | /
           E
      """
      self._run_file("test_buddy_system_with_multi_if")

      with open("junkhacker.log.py") as log_file:
        logs = log_file.read()
        assert logs.count("IN THE TEST") == 7
        assert logs.count("Okay so (0->32) has the buddy (263->263)") == 1
        assert logs.count("Okay so (33->128) has the buddy (141->152)") == 1
        assert logs.count("Okay so (141->152) has the buddy (165->176)") == 1
        assert logs.count("Okay so (165->176) has the buddy (189->200)") == 1
        assert logs.count("Okay so (223->234) has the buddy (247->262)") == 1
        assert logs.count("Okay so (189->200) has the buddy (213->222)") == 1
        assert logs.count("Okay so (213->222) has the buddy (247->262)") == 1


    def _run_file(self, file):
      f = open("files_to_test_against/" + file + ".py")
      source = f.read()

      logger.debug('source is')
      logger.debug(source)

      bytecode_object = BytecodeObject('<string>')
      compiled_code = get_co(source)
      bytecode_object.parse_code(compiled_code)

      logger.debug('Declarations are')
      logger.debug(bytecode_object.declarations)

      logger.debug('bytecode_object.main_module is')
      logger.debug(bytecode_object.main_module)

      # We can save the cflow for each decl
      all_the_decls = {}

      # First loop gets all of the cflow objects for each decl
      for decl in bytecode_object.declarations:
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

      # Now we can pass every cflow object to every decl
      for decl in reversed(bytecode_object.declarations):
        cflow = all_the_decls[decl]
        # Print BasicBlocks
        logger.debug("Blocks in CFG are: ")
        for b in cflow.blocks:
          logger.debug(b)

        logger.debug('dominators.frontier is')
        logger.debug(cflow.dominators.frontier)

        graph = cflow.graph

        # Start new code
        logger.debug("Uh what, # of nodes is %s", len(graph.nodes))
        logger.debug("IN HERE Here they are %s", graph.nodes)
        # Access first element of the set
        for node in graph.nodes:
          if node.kind == 'ENTRY':
            # We just want to run this on the root
            bfs_set_buddies(graph, node)
            # raise
            break
        # End new code

        # If it is not the MAKE_FUNCTION bytecode
        if len(graph.nodes) != 3:
          logger.warn("\n\n\n\n\n\n\nprint nodes after buddy system")
          logger.warn("len(graph.nodes) is %s", len(graph.nodes))
          for node in graph.nodes:
            if node.buddy:
              logger.error("IN THE TEST\nOkay so %s has the buddy %s", node.data.p_range(), node.buddy.data.p_range())
          logger.warn("\n\n\n\n\n\n\n")


    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)
