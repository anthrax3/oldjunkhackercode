"""
  junkhacker.analysis.block
  ~~~~~~~~~~~~~~~~~~~~

  Basic block for the bytecode.
"""

LOAD_NAME = 101
NAME_KIND = 1
STORE_NAME = 90

class BasicBlock(object):
  """
    Represents a basic block from the bytecode.
  """
  ENTRY = 1
  IMPLICIT_RETURN = 2
  UNKNOWN = 3
  LOOP = 4
  IF = 5
  EXCEPT = 6

  def __init__(self, kind, decl, index):
    self.decl = decl
    self.index = index
    self.kind = kind

    self.buddy = None
    self.bytecode_slice = []
    self.end_target = -1
    self.fallthrough = False
    self.false_child = set()
    self.gen = set()
    # has_ret_value may be dead code, I just made a new one
    self.has_ret_value = False
    self.has_return_path = False
    self.has_return_value = False
    self.jumps = set()
    self.kill = set()
    self._length = 0
    self.live_in = set()
    self.live_out = set()
    self.phi = set()
    self.reach_in = set()
    self.reach_out = set()
    self.succ = set()
    self.true_child = set()

  @property
  def length(self):
    return self._length

  @length.setter
  def length(self, value):
    assert value >= 0
    self._length = value

  def clear_jumps(self):
    self.jumps = set()

  def add_jump(self, jump_index, branch_kind):
    self.jumps.add((jump_index, branch_kind))

  def add_gen(self, generated_variable, variable_kind):
    if variable_kind == LOAD_NAME:
      self.gen.add((generated_variable, NAME_KIND))
    else:
      logger.debug('wtf is going on here?')

  def add_kill(self, killed_variable, variable_kind, offset):
    if variable_kind == STORE_NAME:
      self.kill.add((killed_variable, NAME_KIND, offset))
    else:
      logger.debug('wtf is going on here?')

  def add_false_child(self, edge):
    self.false_child.add(edge)

  def add_true_child(self, edge):
    self.true_child.add(edge)

  # def add_phi(self, phi_variable, variable_kind):
  #   self.phi.add((phi_variable, variable_kind))

  # def add_live_in(self, lives_in_variable, variable_kind):
  #   # if variable_kind == LOAD_NAME or variable_kind == STORE_NAME or variable_kind == NAME_KIND:
  #   if variable_kind == NAME_KIND:
  #     self.live_in.add((lives_in_variable, NAME_KIND))
  #   else:
  #     logger.debug('wtf is going on here?')

  # def add_live_out(self, lives_out_variable, variable_kind):

  #   # if variable_kind == LOAD_NAME or variable_kind == STORE_NAME or variable_kind == NAME_KIND:
  #   if variable_kind == NAME_KIND:
  #     self.live_out.add((lives_out_variable, NAME_KIND))
  #   else:
  #     logger.debug('wtf is going on here?')

  def add_succ(self, node):
    self.succ.add(node)

  def p_range(self):
    return '(%d->%d)' % (self.index, (self.index + self.length))

  def __repr__(self):
    end_target = ''
    if self.end_target > -1:
      end_target = ', target=%d' % self.end_target
    # return 'BasicBlock(%d->%d jumps=%s succ=%s)' \
    #        % (self.index, (self.index + self.length), self.jumps, self.succ)

    if self.buddy:
      return 'BasicBlock(%d->%d) BUDDY IS --%s-- has_ret_val is %s' \
             % (self.index, (self.index + self.length), self.buddy, self.has_ret_value)

    return 'BasicBlock(%d->%d) has_ret_val is %s' \
             % (self.index, (self.index + self.length), self.has_ret_value)


    # return 'BasicBlock(%s, %d->%d, gen=%s kill=%s live_in=%s live_out=%s reach_in=%s reach_out=%s succ= %s jumps=%s%s)' \
    #        % (self.kind, self.index, (self.index + self.length), self.gen, self.kill, self.live_in, self.live_out, self.reach_in, self.reach_out, self.succ, self.jumps, end_target)
