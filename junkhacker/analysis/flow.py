"""
  junkhacker.analysis.flow
  ~~~~~~~~~~~~~~~~~~~

  Extract the control flow graphs from the bytecode.
"""
import dis
import opcode

from collections import defaultdict
from itertools import izip, tee
from operator import attrgetter, itemgetter

from .basicBlockInterpreter import BasicBlockInterpreter
from .block import BasicBlock
from ..bytecode.decl import Declaration
from ..bytecode.utils import show_bytecode
from .graph import DiGraph, Edge, EdgeVisitor, Node, Walker
from .graph.dominators import DominatorTree
from ..utils.log import logger
import logging

# logger.setLevel(logging.CRITICAL)

BREAK_LOOP = 80
FOR_ITER = 93
JUMP_ABSOLUTE = 113
JUMP_FORWARD = 110
JUMP_IF_FALSE_OR_POP = 111
JUMP_IF_TRUE_OR_POP = 112
JUMP_OPCODES = opcode.hasjabs + opcode.hasjrel
LOAD_GLOBAL = 116
LOAD_NAME = 101
POP_JUMP_IF_FALSE = 114
POP_JUMP_IF_TRUE =  115
RAISE_VARARGS = 130
RETURN_VALUE = 83
SETUP_EXCEPT = 121
SETUP_FINALLY = 122
SETUP_LOOP = 120
STORE_NAME = 90
SETUP_WITH = 143

## Taint tracking
# EXEC_STMT = 85
# GLOBAL_SINKS = ['redirect', 'open', 'globals', 'HttpResponse']

# BYTECODE_SINKS = [EXEC_STMT]
NO_FALL_THROUGH = (JUMP_ABSOLUTE, JUMP_FORWARD)

class ControlFlow(object):
  """
    Performs the control-flow analysis on a ``Declaration`` object. It iterates
    over its bytecode and builds the basic block. The final representation
    leverages the ``DiGraph`` structure, and contains an instance of the
    ``DominatorTree``.
  """
  E_COND = 'COND'
  E_END_LOOP = 'END_LOOP'
  E_EXCEPT = 'EXCEPT'
  E_FALSE = 'FALSE'
  E_FINALLY = 'FINALLY'
  E_RAISE = 'RAISE'
  E_RETURN = 'RETURN'
  E_TRUE = 'TRUE'
  E_UNCOND = 'UNCOND'

  N_CONDITION = 'CONDITION'
  N_ENTRY = 'ENTRY'
  N_EXCEPT = 'EXCEPT'
  N_IF = 'IF'
  N_IMPLICIT_RETURN = 'IMPLICIT_RETURN'
  N_LOOP = 'LOOP'
  N_UNKNOWN = ''

  CFG_TMP_BREAK = -1
  CFG_TMP_RAISE = -2
  CFG_TMP_RETURN = -3

  def __init__(self, decl):
    self.decl = decl

    # The basic blocks created during the control flow analysis.
    self.blocks = None
    # Maps bytecode indices and basic blocks.
    self.block_idx_map = {}
    # Maps basic blocks and CFG nodes.
    self.block_nodes = {}
    self.bytecode_sink_lines = set()
    self.dom = None
    self.entry = None
    self.exit = None
    self.entry_node = None
    self.exit_node = None
    self.frames = None
    self.global_sink_lines = set()

    self.graph = None
    self.root = None
    self.vardict = {}

    self.analyze()

  def __repr__(self):
    return 'ControlFlow(blocks=%s dom=%s entry=%s exit=%s entry_node=%s exit_node=%s graph=%s vardict=%s)' \
           % (self.blocks, self.dominators, self.entry, self.exit, self.entry_node, self.exit_node, self.graph, self.vardict)

  @property
  def dominators(self):
    """
      Returns the ``DominatorTree`` that contains:
       - Dominator tree (dict of IDom)
       - Post dominator tree (doc of PIDom)
       - Dominance frontier (dict of CFG node -> set CFG nodes)
    """
    if self.dom is None:
      self.dom = DominatorTree(self)
    return self.dom

  def analyze(self):
    """
      Performs the CFA and stores the resulting CFG.
    """
    bytecode = self.decl.bytecode

    self.entry = BasicBlock(BasicBlock.ENTRY, self.decl, -1)
    self.exit = BasicBlock(BasicBlock.IMPLICIT_RETURN, self.decl, -1)

    self.blocks = ControlFlow.make_blocks(self.decl, bytecode)

    # TODO: explain this better
    # self.decl.bytecode is a list of tuples, co_names is in index 5
    variables = list(self.decl.bytecode[0][5].co_names)
    self.vardict = dict((k,-1) for k in variables)

    self.__build_flowgraph(bytecode)
    # logger.debug("CFG(%s) :=\n%s", self.decl, self.graph.to_dot())

  @classmethod
  def merge_tainted_bys(cls, d1, d2):
    logger.debug("d1 is %s\nd2 is %s", d1, d2)
    # Thanks Eli Bendersky
    result = defaultdict(list)
    for d in (d1, d2):
      for key, value in d.iteritems():
        dupe = False
        # I seriously need to stop doing this :(
        for sorry in result[key]:
          if sorry == value:
            dupe = True
        if not dupe:
          result[key].append(value)
    logger.debug("result is %s", result)
    return result

  @classmethod
  def taint_propagation(cls, current_block, current_decl, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='', counter=None, other_decls=None, last_block_instruction=None, interprocedural_mode=False, stack_of_buddies=[], score=[], tainted_by={}):
    """
      Forward flow from root to leaves,

      :param tainted: The current list of tainted variables.
      :param stack: The stack of the previously executed basic blocks.
      :param environment: The environment of the previously executed basic blocks.
    """
    if not counter:
      counta = 1
    else:
      counta = counter+1

    logger.debug('\n\n\n\n\nNEW INVOCATION OF taint_propagation, counter is %s !!! current_block.bytecode_slice is', str(counta))
    logger.debug(current_block.bytecode_slice)
    logger.debug('tainted is')
    logger.debug(tainted)
    logger.debug('current_block is')
    logger.debug(current_block)

    logger.debug('last_block_instruction is %s', last_block_instruction)

    # So we don't add to the parents set
    new_set_of_previous_edges = previous_edges.copy()

    if new_edge is not '':
      new_set_of_previous_edges.add(new_edge)
    logger.debug('new_set_of_previous_edges is')
    logger.debug(new_set_of_previous_edges)
    logger.debug("[buddy system]STACK OF BUDDIES IS %s", stack_of_buddies)


    current_interpreter = BasicBlockInterpreter(list(stack), current_decl, tainted.copy(), environment.copy(), immune.copy(), other_decls, interprocedural_mode=interprocedural_mode, score=score, tainted_by=tainted_by)

    last_op = ''
    last_offset = 0
    # Excute the current BasicBlock
    for current_block_bytecode in current_block.bytecode_slice:
      offset, lineno, op, arg, _, _ = current_block_bytecode
      logger.debug('\n\n\n\ncurrent_block_bytecode is: op is '+dis.opname[op]+', lineno is '+str(lineno)+', offset is '+str(offset)+' and arg is '+str(arg))
      logger.debug('before dispatch')
      logger.debug(current_interpreter)
      current_interpreter.dispatch(dis.opname[op], arg, lineno)
      logger.debug('after dispatch')
      logger.debug(current_interpreter)

      last_op = dis.opname[op]
      last_offset = offset

    logger.debug('IMPORTANT FOR RET VALS\nThe last op was %s at offset %s',last_op, last_offset)
    logger.debug('last_block_instruction is %s', last_block_instruction)

    # We only do something if last_offset is greater than 999999999999
    # Only used with FOR_ITER to know if a back-edge or not.
    last_block_instruction_offset = 999999999999

    if last_block_instruction:
      last_block_instruction_op, last_block_instruction_offset = last_block_instruction
      logger.debug('last_block_instruction_op is %s and last_block_instruction_offset is %s', last_block_instruction_op, last_block_instruction_offset)

    logger.debug('after loop, current_interpreter is')

    logger.debug(current_interpreter)

    if current_block.has_ret_value:
      curr_top = current_interpreter.top()
      curr_tainted = current_interpreter.tainted
      logger.debug("hhhhhhhghiWith block %s, TOS is %s and tainted is %s", current_block , curr_top, curr_tainted)
      if curr_top in curr_tainted:
        logger.debug("Holy motherfucker")
        current_decl.returns_tainted = True


    # Recurse no more!
    if counta > 23:
      logger.error("Giving up, too many recursions, counta is %s", counta)
      # return current_interpreter

    if stack_of_buddies:
      logger.debug("WOOHOO, stack_of_buddies is \n%s and \ncurrent_block is \n\t%s\ncurrent_block.succ is \n\t%s", stack_of_buddies, current_block, current_block.succ)

      x = set()
      x.add(stack_of_buddies[-1])
      if current_block.succ == x:
        logger.debug("So current_bloc.succ == stack_of_buddies[-1]")
        return current_interpreter
      else:
        logger.debug("Well shit, current_block.succ is %s and x is %s", current_block.succ, x)
        logger.debug("Well shit, current_block.succ is %s and stack_of_buddies[-1] is %s", current_block.succ, stack_of_buddies[-1])

    if current_decl:
      logger.debug("https://www.youtube.com/watch?v=Z6YbZ0hZQYM Hmm method_name is %s", current_decl.method_name)

    if current_block.buddy:
      stack_of_buddies.append(current_block.buddy)
      logger.debug("Okay, mother fucker. current_block is %s\n len(stack_of_buddies) is %s\n stack_of_buddies is %s", current_block, len(stack_of_buddies), stack_of_buddies)


    kids_tainted_sets = []
    kids_tainted_by_dicts = []
    kids_stacks = []
    kids_environments = []
    # So? Does "new_set_of_previous_edges = previous_edges.copy()" fuck with us?

    kid_interpreter = None
    # Here is where we need to take the buddy system into account
    for child_block in current_block.succ:
      if stack_of_buddies:
        if child_block == stack_of_buddies[-1]:
          logger.error("ROUTES So current_block %s and child_block is %s", current_block, stack_of_buddies[-1])
      if child_block == current_block.buddy:
        logger.error("Well mother fucker, I don't want to execute you now")
        continue
      logger.debug("NEW CHILD")
      edge = str(current_block.index)+"->"+str(child_block.index)
      logger.debug("Edge is %s", edge)
      logger.debug("The current_interpreter is %s",current_interpreter)


      # If the pop is conditional on whether or not the FALSE branch is taken e.g. and
      if edge in current_block.true_child and last_op is "JUMP_IF_FALSE_OR_POP":
        logger.debug("Cleaning a leftover %s due to a %s instruction at edge %s",current_interpreter.top(), last_op, edge)
        kid_interpreter = cls.taint_propagation(child_block, current_decl, current_interpreter.tainted, current_interpreter.stack[:-1], current_interpreter.environment, current_interpreter.immune, new_set_of_previous_edges, edge, counta, other_decls, last_block_instruction=(last_op, last_offset), interprocedural_mode=interprocedural_mode, stack_of_buddies=list(stack_of_buddies), score=score, tainted_by=tainted_by)
      # If the pop is conditional on whether or not the TRUE branch is taken e.g. or
      elif edge in current_block.false_child and last_op is "JUMP_IF_TRUE_OR_POP":
        logger.debug("Cleaning a leftover %s due to a %s instruction at edge %s",current_interpreter.top(), last_op, edge)
        kid_interpreter = cls.taint_propagation(child_block, current_decl, current_interpreter.tainted, current_interpreter.stack[:-1], current_interpreter.environment, current_interpreter.immune, new_set_of_previous_edges, edge, counta, other_decls, last_block_instruction=(last_op, last_offset), interprocedural_mode=interprocedural_mode, stack_of_buddies=list(stack_of_buddies), score=score, tainted_by=tainted_by)
      elif edge in current_block.false_child and last_op is "FOR_ITER" and last_block_instruction_offset < last_offset:
        logger.debug("Cleaning a leftover %s due to a %s instruction at edge %s",current_interpreter.top(), last_op, edge)
        kid_interpreter = cls.taint_propagation(child_block, current_decl, current_interpreter.tainted, current_interpreter.stack[:-1], current_interpreter.environment, current_interpreter.immune, new_set_of_previous_edges, edge, counta, other_decls, last_block_instruction=(last_op, last_offset), interprocedural_mode=interprocedural_mode, stack_of_buddies=list(stack_of_buddies), score=score, tainted_by=tainted_by)
      # If we're repeating ourselves
      elif edge in new_set_of_previous_edges:
        logger.debug('edge %s is already in %s', edge, str(new_set_of_previous_edges))
        continue
      else:
        logger.debug('before edge is %s', edge)
        logger.debug('after new_set_of_previous_edges is %s', new_set_of_previous_edges)
        kid_interpreter = cls.taint_propagation(child_block, current_decl, current_interpreter.tainted, current_interpreter.stack, current_interpreter.environment, current_interpreter.immune, new_set_of_previous_edges, edge, counta, other_decls, last_block_instruction=(last_op, last_offset), interprocedural_mode=interprocedural_mode, stack_of_buddies=list(stack_of_buddies), score=score, tainted_by=tainted_by)

      kids_tainted_sets.append(kid_interpreter.tainted)
      kids_tainted_by_dicts.append(kid_interpreter.tainted_by)
      kids_stacks.append(kid_interpreter.stack)
      kids_environments.append(kid_interpreter.environment)
    # Jump to the buddy and start executing!
    if current_block.buddy:
      logger.debug("I have a buddy, I am %s", current_block)
      if len(stack_of_buddies) > 0:
        logger.debug("I also have a stack_of_buddies %s", stack_of_buddies)

      logger.debug("Aight so the len(kids_tainted_sets) are %s", len(kids_tainted_sets))
      logger.debug("Aight so the kids_tainted_sets are %s", kids_tainted_sets)
      logger.debug("Aight so the kids_stacks are %s", kids_stacks)
      logger.debug("Aight so the kids_environments are %s", kids_environments)

      assert len(kids_tainted_sets) < 3
      # It is only good for 2 kids, because a node can only have 2 kids
      if len(kids_tainted_sets) == 2:
        logger.debug("0 is %s", kids_tainted_sets[0])
        logger.debug("1 is %s", kids_tainted_sets[1])
        together = kids_tainted_sets[0].union(kids_tainted_sets[1])

        resulted_tainted_bys = cls.merge_tainted_bys(kids_tainted_by_dicts[0], kids_tainted_by_dicts[1])
      elif len(kids_tainted_sets) == 1:
        # Should only be true when the "if child_block == current_block.buddy" from above is true
        together = kids_tainted_sets[0].union(current_interpreter.tainted)
        resulted_tainted_bys = cls.merge_tainted_bys(kids_tainted_by_dicts[0], current_interpreter.tainted_by)
      logger.debug("together is %s", together)
      logger.debug("resulted_tainted_bys is %s", resulted_tainted_bys)

      # This should always be true
      assert current_block.buddy == stack_of_buddies[-1]

      if len(stack_of_buddies) > 1:
        # if current_block.buddy == stack_of_buddies[-2]:
        if stack_of_buddies[-1] == stack_of_buddies[-2]:
          logger.warn("STARBUCKS current_block is %s current_block.buddy is %s stack_of_buddies is %s", current_block, current_block.buddy, stack_of_buddies)
          logger.warn("STARBUCKS current_interpreter.tainted is %s", current_interpreter.tainted)

          # Merge the children tainted sets with our own
          current_interpreter.tainted = current_interpreter.tainted.union(together)

          # Merge the children tainted_by dictionaries with our own
          current_interpreter.tainted_by = cls.merge_tainted_bys(current_interpreter.tainted_by, resulted_tainted_bys)

          stack_of_buddies = stack_of_buddies[:-1]

          # Do not continue, parent will do that
          return current_interpreter

      logger.warn("Proceeding as 1 to my buddy")
      # Jump to buddy, proceed as 1
      cls.taint_propagation(current_block.buddy, current_decl, together, kid_interpreter.stack, kid_interpreter.environment, kid_interpreter.immune, new_set_of_previous_edges, '', counta, other_decls, last_block_instruction=None, interprocedural_mode=interprocedural_mode, stack_of_buddies=stack_of_buddies[:-1], score=score, tainted_by=tainted_by)

    # return (current_interpreter.stack, tainted, current_interpreter.environment)
    logger.debug("current_interpreter.stack is %s", current_interpreter.stack)
    logger.debug("stack_of_buddies is %s", stack_of_buddies)
    return current_interpreter


  def __liveness_analysis(self):
    """
      Calculates live_in and live_out sets for every node. Traverses the RPOi.
    """
    rpoi = self.dominators.rpoi
    live_in_of_succs = set()

    for node in rpoi:
      node.data.live_in.update(node.data.gen)
      node.data.live_in.update(live_in_of_succs)
      # live_out += live_in_of_succs
      node.data.live_out.update(live_in_of_succs)
      # Format the kill set to take out the bytecode offset
      formatted_kill_set = set()
      for variable in node.data.kill:
        formatted_kill_set.update((variable[0:2],)) # This tuple syntax is so fucky
      # Add our own live_in to the pile
      live_in_of_succs.update(node.data.live_in)
      # Make sure anything in gen isn't in the formatted_kill_set
      formatted_kill_set.difference_update(node.data.gen)
      # Subtract the kill set
      node.data.live_in.difference_update(formatted_kill_set)
      live_in_of_succs.difference_update(formatted_kill_set)
    logger.debug('after, rpoi is')
    logger.debug(rpoi)

  def __reaching_definitions(self):
    """
      Calculates reach_in and reach_out sets for every node. Traverses the RPO.
      Totally might be broken.
    """
    rpo = self.dominators.rpo
    reach_out_of_preds = set()

    for node in rpo:
      # reach_out += reach_out_of_preds
      node.data.reach_in.update(reach_out_of_preds)

      #Subtract redefs
      # Format the def and reach_out_of_preds sets to take out the bytecode offset
      formatted_def_set = set()
      formatted_reach_out_of_preds = set()
      for variable in node.data.kill:
        formatted_def_set.update((variable[0:2],)) # This tuple syntax is so fucky
      for variable in reach_out_of_preds:
        formatted_reach_out_of_preds.update((variable[0:2],)) # This tuple syntax is so fucky

      redef_set = formatted_def_set.intersection(formatted_reach_out_of_preds)

      remove_this = set()
      for variable in reach_out_of_preds:
        if variable[0:2] in redef_set:
          remove_this.add(variable)

      # reach_out_of_preds - redefs!
      reach_out_of_preds.difference_update(remove_this)
      #Subtract redefs
      node.data.reach_out.update(node.data.kill)
      # U (Rin-REDEFs)
      node.data.reach_out.update(reach_out_of_preds)

      # Add our own reach_out to the pile
      reach_out_of_preds.update(node.data.reach_out)

    logger.debug('rpo at the end of __reaching_definitions is finally')
    logger.debug(rpo)

  def __build_flowgraph(self, bytecode):
    g = DiGraph(multiple_edges=False)
    self.entry_node = g.make_add_node(kind=ControlFlow.N_ENTRY, data=self.entry)
    self.exit_node = g.make_add_node(kind=ControlFlow.N_IMPLICIT_RETURN, data=self.exit)

    self.block_idx_map = {}
    self.block_nodes = {}

    # Connect entry/implicit return blocks
    last_block_index, last_block = -1, None
    for block in self.blocks:
      self.block_idx_map[block.index] = block
      node_kind = ControlFlow.get_kind_from_block(block)
      block_node = g.make_add_node(kind=node_kind, data=block)
      self.block_nodes[block] = block_node
      if block.index == 0:
        g.make_add_edge(self.entry_node, self.block_nodes[block], kind=ControlFlow.E_UNCOND)
        # logger.debug('self.block_nodes[block].data type is BasicBlock!')
        # logger.debug(type(self.block_nodes[block].data))

        # Add self.block_nodes[block].data to succ of self.entry_node
        self.entry_node.data.add_succ(self.block_nodes[block].data)
      if block.index >= last_block_index:
        last_block = block
        last_block_index = block.index
    g.make_add_edge(self.block_nodes[last_block], self.exit_node, kind=ControlFlow.E_UNCOND)
    # Add self.exit_node to succ of self.block_nodes[last_block]

    sorted_blocks = sorted(self.blocks, key=attrgetter('index'))
    i, length = 0, len(sorted_blocks)

    logger.debug('The sorted_blocks are')
    logger.debug(sorted_blocks)

    while i < length:
      cur_block = sorted_blocks[i]
      if cur_block.jumps:
        # Connect the current block to its jump targets
        for (jump_index, branch_kind) in cur_block.jumps:
          # We don't do this if it's a break, return or raise
          if jump_index <= ControlFlow.CFG_TMP_BREAK:
            continue
          target_block = self.block_idx_map[jump_index]
          logger.debug('cur_block is ')
          logger.debug(cur_block)
          logger.debug('self.block_nodes[cur_block] is ')
          logger.debug(self.block_nodes[cur_block])
          logger.debug('self.block_nodes[target_block] is ')
          logger.debug(self.block_nodes[target_block])

          # Add target_block to the succ of the cur_block!
          cur_block.add_succ(target_block)

          logger.debug('branch_kind is ')
          logger.debug(branch_kind)
          if branch_kind is 'TRUE':
            logger.debug("cur_block is %s and target is %s",cur_block.index, target_block.index)
            cur_block.add_true_child(str(cur_block.index)+"->"+str(target_block.index))
          if branch_kind is 'FALSE':
            logger.debug("cur_block is %s and target is %s",cur_block.index, target_block.index)
            cur_block.add_false_child(str(cur_block.index)+"->"+str(target_block.index))

          g.make_add_edge(self.block_nodes[cur_block], self.block_nodes[target_block], kind=branch_kind)
      i += 1

    self.graph = g
    self.__finalize()


    # Handle optimizations that left unreachable JUMPS, see https://github.com/neuroo/equip/issues/2
    for node in self.graph.roots():
      if node.kind == ControlFlow.N_ENTRY:
        continue
      logger.warn("So type(node.data) is %s", type(node.data))
      index, lineno, op, arg, cflow_in, code_object = node.data.bytecode_slice[0]
      if op in JUMP_OPCODES:
        self.graph.remove_node(node)


    i = len(sorted_blocks)-1

    logger.debug('AFTER ADDING succs sorted_blocks is')
    logger.debug(sorted_blocks)

    self.__liveness_analysis()
    self.__reaching_definitions()


    # Pass the root of the DominatorTree
    logger.debug('IMPORTANT')
    logger.debug('self.dominators.dom.keys()')
    logger.debug(self.dominators.dom.keys())
    logger.debug('IMPORTANT')
    logger.debug('type(self.dominators.dom.keys()[0].data)')
    logger.debug(type(self.dominators.dom.keys()[0].data))
    logger.debug('self.dominators.dom.keys()[0].data)')
    logger.debug(self.dominators.dom.keys()[0].data)
    # root = self.dominators.dom.keys()[0].data
    # logger.debug('root is:')
    # logger.debug(root)

    # assert root.index == -1
    import sys
    n = sys.getrecursionlimit()
    logger.debug("max getrecursionlimit")
    logger.debug(n)
    sys.setrecursionlimit(50000)
    # assert root.length == 0

    logger.debug('so maybe self.dominators.rpo is better to loop through')
    logger.debug(self.dominators.rpo)

    i = 1
    self.root = self.dominators.rpo[0].data
    logger.debug(str(i)+": ")
    logger.debug(self.root)
    logger.debug(type(self.root))
    for node in self.root.succ:
      i = i + 1
      logger.debug(str(i)+": ")
      logger.debug(node)
      if node.succ:
        for foo in node.succ:
          i = i + 1
          logger.debug(str(i)+": ")
          logger.debug(foo)
          if foo.succ:
            for how in foo.succ:
              i = i + 1
              logger.debug(str(i)+": ")
              logger.debug(how)
              # ...






  def __finalize(self):
    def has_true_false_branches(list_edges):
      has_true, has_false = False, False
      for edge in list_edges:
        if edge.kind == ControlFlow.E_TRUE: has_true = True
        elif edge.kind == ControlFlow.E_FALSE: has_false = True
      return has_true and has_false

    def get_cfg_tmp_values(node):
      values = set()
      for (jump_index, branch_kind) in node.data.jumps:
        # Add it if it's a break, return or raise
        if jump_index <= ControlFlow.CFG_TMP_BREAK:
          values.add(jump_index)
      return values

    def get_parent_loop(node):
      class BwdEdges(EdgeVisitor):
        def __init__(self):
          EdgeVisitor.__init__(self)
          self.edges = []

        def visit(self, edge):
          self.edges.append(edge)

      visitor = BwdEdges()
      walker = Walker(self.graph, visitor, backwards=True)
      walker.traverse(node)
      parents = visitor.edges

      logger.debug('parents are ')
      logger.debug(parents)

      node_bc_index = node.data.index
      for parent_edge in parents:
        parent = parent_edge.source
        if parent.kind != ControlFlow.N_LOOP:
          continue
        # Find the loop in which the break/current node is nested in
        if parent.data.index < node_bc_index and parent.data.end_target > node_bc_index:
          logger.debug('ghi parent is ')
          logger.debug(parents)

          return parent
      return None

    # Burn N_CONDITION nodes
    for node in self.graph.nodes:
      out_edges = self.graph.out_edges(node)
      if len(out_edges) < 2 or not has_true_false_branches(out_edges):
        continue

      # LOOP is more specific than CONDITION
      if node.kind is not ControlFlow.N_LOOP:
        node.kind = ControlFlow.N_CONDITION

# temp
    # get_parent_loop(node)
# temp

    # Handle return/break statements:
    #  - blocks with returns are simply connected to the IMPLICIT_RETURN
    #    and previous out edges removed
    #  - blocks with breaks are connected to the end of the current loop
    #    and previous out edges removed
    for node in self.graph.nodes:
      cfg_tmp_values = get_cfg_tmp_values(node)
      if not cfg_tmp_values:
        continue
      if ControlFlow.CFG_TMP_BREAK in cfg_tmp_values:
        parent_loop = get_parent_loop(node)
        if not parent_loop:
          logger.error("Cannot find parent loop for %s", node)
          continue
        target_block = self.block_idx_map[parent_loop.data.end_target]

        out_edges = self.graph.out_edges(node)
        for edge in out_edges:
          self.graph.remove_edge(edge)

        self.graph.make_add_edge(node, self.block_nodes[target_block], kind=ControlFlow.E_UNCOND)
      if ControlFlow.CFG_TMP_RETURN in cfg_tmp_values:
        # Remove existing out edges and add a RETURN edge to the IMPLICIT_RETURN
        out_edges = self.graph.out_edges(node)
        for edge in out_edges:
          self.graph.remove_edge(edge)
        self.graph.make_add_edge(node, self.exit_node, kind=ControlFlow.E_RETURN)

  BLOCK_NODE_KIND = {
    BasicBlock.UNKNOWN: N_UNKNOWN,
    BasicBlock.ENTRY: N_ENTRY,
    BasicBlock.IMPLICIT_RETURN: N_IMPLICIT_RETURN,
    BasicBlock.LOOP: N_LOOP,
    BasicBlock.IF: N_IF,
    BasicBlock.EXCEPT: N_EXCEPT,
  }

  @staticmethod
  def get_kind_from_block(block):
    return ControlFlow.BLOCK_NODE_KIND[block.kind]

  @staticmethod
  def get_pairs(iterable):
    a, b = tee(iterable)
    next(b, None)
    return izip(a, b)

  @staticmethod
  def make_blocks(decl, bytecode):
    """
      Returns the set of ``BasicBlock`` that are encountered in the current bytecode.
      Each block is annotated with its qualified jump targets (if any).

      :param decl: The current declaration object.
      :param bytecode: The bytecode associated with the declaration object.
    """
    blocks = set()
    block_map = {} # bytecode index -> block

    i, length = 0, len(bytecode)
    # TODO Explain these 3 lines
    start_index = [j for j in range(length) if bytecode[j][0] == 0][0]
    prev_co = bytecode[start_index][5]
    slice_bytecode = [tpl for tpl in bytecode[start_index:] if tpl[5] == prev_co]

    logger.debug("Current slice_bytecode:\n%s", slice_bytecode)
    logger.debug("Current bytecode:\n%s", show_bytecode(slice_bytecode))
    slice_length = len(slice_bytecode)
    known_targets = ControlFlow.find_targets(slice_bytecode)
    known_targets.add(0)
    known_targets.add(1 + max([tpl[0] for tpl in slice_bytecode]))
    known_targets = list(known_targets)
    known_targets.sort()

    # Print the range of each BasicBlock in [(a, b), (b, c), ...] form
    logger.debug("Targets: %s\n", [d for d in ControlFlow.get_pairs(known_targets)])

    slice_bytecode_indexed = {}
    idx = 0
    for l in slice_bytecode:
      index = l[0]
      slice_bytecode_indexed[index] = (l, idx)
      idx += 1

    for start_index, end_index in ControlFlow.get_pairs(known_targets):
      logger.debug('start_index is '+str(start_index)+' and end_index is '+str(end_index)+'\n')
      offset, _, op, arg, _, _ = slice_bytecode_indexed[start_index][0]
      block_kind = ControlFlow.block_kind_from_op(op)
      cur_block = BasicBlock(block_kind, decl, start_index)
      cur_block.length = end_index - start_index - 1

      # Clean this up, what exception?
      i = slice_bytecode_indexed[start_index][1]
      try:
        length = slice_bytecode_indexed[end_index][1]
        if length >= slice_length:
          length = slice_length
      except:
        length = slice_length

      while i < length:
        offset, lineno, op, arg, _, _ = slice_bytecode[i]
        cur_block.bytecode_slice.append(slice_bytecode[i])
        # cur_block.bytecode_slice.extend(slice_bytecode[i])

        # Not that helpful
        # logger.debug('slice_bytecode['+str(i)+'] is ')
        # logger.debug(slice_bytecode[i])

#         # If we're loading a global sink
#         if arg in GLOBAL_SINKS and op is LOAD_GLOBAL:
#           logger.debug('Uh oh Spaghettios sink on line '+str(lineno))
#           # self.global_sink_lines.add(lineno)

#           # What's the argument to the sink?

#           # TODO why the fuck is this not a whole BasicBlock?

#           logger.debug('i is '+str(i)+' and length is '+str(length))
#           intepreter = BasicBlockInterpreter()


# # FIX THIS SHIT
#           # for x in xrange(start_index, end_index):
#           for x in xrange(i, length):
#             logger.debug('x is '+str(x))
#             roffset, _, rop, rarg, _, _ = slice_bytecode[x]
#             logger.debug('op is '+dis.opname[rop]+', roffset is '+str(roffset)+' and rarg is '+str(rarg))
#             intepreter.dispatch(dis.opname[rop], rarg)
#           logger.debug('intepreter stack is')
#           logger.debug(intepreter.stack)
#           # logger.debug('intepreter call_function_arguments is')
#           # logger.debug(intepreter.call_function_arguments)
#           logger.debug('intepreter called_functions is')
#           logger.debug(intepreter.called_functions)
#           # self.__find_arg_to_sink(slice_bytecode_indexed[start_index][0], slice_bytecode_indexed[start_index][1], length)

#         elif op in BYTECODE_SINKS:
#           logger.debug('Uh oh Spaghettios bytecode sink on line '+str(lineno))
#           # self.bytecode_sink_lines.add(lineno)


        # Make KILL set for NAMEs
        if op == STORE_NAME:
          logger.debug('arg (aka variable being stored into) is')
          logger.debug(arg)
          logger.debug('STORE_NAME is')
          logger.debug(STORE_NAME)
          # The set of variables that are assigned a value in cur_block
          cur_block.add_kill(arg, STORE_NAME, offset)

        # Make GEN set for NAMEs
        if op == LOAD_NAME:
          logger.debug('arg (aka variable being loaded) is')
          logger.debug(arg)
          logger.debug('LOAD_NAME is')
          logger.debug(LOAD_NAME)
          # The set of variables that are used in cur_block before any assignment.
          if arg not in cur_block.kill:
            cur_block.add_gen(arg, LOAD_NAME)

        if op in JUMP_OPCODES:
          jump_address = arg
          if op in opcode.hasjrel:
            jump_address = arg + offset + 3

          if op in (SETUP_FINALLY, SETUP_EXCEPT, SETUP_WITH):
            kind = ControlFlow.E_UNCOND
            if op == SETUP_FINALLY: kind = ControlFlow.E_FINALLY
            if op in (SETUP_EXCEPT, SETUP_WITH): kind = ControlFlow.E_EXCEPT
            cur_block.end_target = jump_address
            cur_block.add_jump(jump_address, kind)

          elif op in (JUMP_ABSOLUTE, JUMP_FORWARD):
            cur_block.add_jump(jump_address, ControlFlow.E_UNCOND)

          elif op in (POP_JUMP_IF_FALSE, JUMP_IF_FALSE_OR_POP, FOR_ITER):
            cur_block.add_jump(jump_address, ControlFlow.E_FALSE)

          elif op in (POP_JUMP_IF_TRUE, JUMP_IF_TRUE_OR_POP):
            cur_block.add_jump(jump_address, ControlFlow.E_TRUE)

          elif op == SETUP_LOOP:
            # This means the next BasicBlock is a LOOP not this one, so no cur_block.kind = BasicBlock.LOOP
            cur_block.end_target = jump_address

        elif op == RETURN_VALUE:
          cur_block.has_return_path = True
          cur_block.has_return_value = True
          cur_block.add_jump(ControlFlow.CFG_TMP_RETURN, ControlFlow.E_RETURN)

        elif op == BREAK_LOOP:
          cur_block.has_return_path = True
          cur_block.add_jump(ControlFlow.CFG_TMP_BREAK, ControlFlow.E_UNCOND)

        elif op == RAISE_VARARGS:
          cur_block.has_return_path = False
          cur_block.add_jump(ControlFlow.CFG_TMP_RAISE, ControlFlow.E_UNCOND)

        i += 1

      # If the last block is not a NO_FALL_THROUGH, we connect the fall through
      if not cur_block.has_return_path and op not in NO_FALL_THROUGH and i < slice_length:
        kind = ControlFlow.E_UNCOND
        if op in (POP_JUMP_IF_FALSE, JUMP_IF_FALSE_OR_POP, FOR_ITER):
          kind = ControlFlow.E_TRUE
        if op in (POP_JUMP_IF_TRUE, JUMP_IF_TRUE_OR_POP):
          kind = ControlFlow.E_FALSE

        cur_block.fallthrough = True
        fallthrough_address = slice_bytecode[i][0]
        cur_block.add_jump(fallthrough_address, kind)
      else:
        cur_block.fallthrough = False

      block_map[start_index] = cur_block
      blocks.add(cur_block)

    return blocks

  @staticmethod
  def block_kind_from_op(op):
    if op in (FOR_ITER,):
      return BasicBlock.LOOP
    # Cannot make the decision at this point, need to await the finalization
    # of the CFG
    return BasicBlock.UNKNOWN

  @staticmethod
  def find_targets(bytecode):
    targets = set()
    i, length = 0, len(bytecode)
    while i < length:
      offset, _, op, arg, _, _ = bytecode[i]
      if op in JUMP_OPCODES:
        jump_address = arg
        if op in opcode.hasjrel:
          jump_address = arg + offset + 3
        targets.add(jump_address)

        if op not in NO_FALL_THROUGH:
          targets.add(bytecode[i + 1][0])
      i += 1
    return targets


