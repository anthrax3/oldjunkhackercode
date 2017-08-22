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

logutils.enableLogger(to_file='./junkhacker.log.py')


def test_delete_false_positives():
  """
  Test out huge mother fucker against fixed dominator code.
  This means both
      the buddy system worked.
      the dominators fix worked.
  """
  f = open("files_to_test_against/test_delete_false_positives.py")
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
