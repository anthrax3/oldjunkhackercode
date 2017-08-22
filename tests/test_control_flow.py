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

SIMPLE_PROGRAM = """
import random
import sys

a = lambda x, y: x + (y if foo == 'bar' else x)

def some_value(i):
  if (i % 2) == 0:
    print "even",
  elif foobar:
    print "whatever"
  else:
    print "odd",

  for n in range(2, 10):
    for x in range(2, n):
      if n % x == 0:
        print n, 'equals', x, '*', n/x
        break
      print "foobar"
    else:
      # loop fell through without finding a factor
      print n, 'is a prime number'

  print "number: %d" % i
  return i - 1


def ask_ok(prompt, retries=4, complaint='Yes or no, please!'):
  while True:
    ok = raw_input(prompt)
    if ok in ('y', 'ye', 'yes'):
      return True
    if ok in ('n', 'no', 'nop', 'nope'):
      return False
      print False
    retries = retries - 1
    if retries < 0:
      raise IOError('refusenik user')
      print "Never reached"
    print complaint

  if foobar:
    print "whatever"


def with_stmt(something):
  with open('output.txt', 'w') as f:
    f.write('Hi there!')

def exception_tests():
  try:
    fd = open('something')
  except SomeException, ex:
    print "SomeException"
  except Exception, ex:
    print "Last Exception"
  finally:
    print "Finally"

def while_loop(data, start):
  while start < len(data):
    print start
    start += 1
    if start > 10:
      return -1

def main():
  for i in range(1, random.randint()):
    print some_value(i)

  print "Call stats:"
  items =  sys.callstats().items()
  items = [(value, key) for key, value in items]
  items.sort()
  items.reverse()
  for value,key in items:
    print "%30s: %30s"%(key, value)


def return_Stmts(i):
  if i == 1:
    return 1
  elif i == 2:
    return 2

  print "This is something else"


if __name__ == '__main__':
  main()
"""

def test_cflow1():
  co_simple = get_co(SIMPLE_PROGRAM)
  assert co_simple is not None
  print 'hi'

  bytecode_object = BytecodeObject('<string>')
  bytecode_object.parse_code(co_simple)

  assert len(bytecode_object.declarations) == 9

  for decl in bytecode_object.declarations:
    print 'Decl is '
    print decl
    print 'cflow is '
    cflow = ControlFlow(decl)

    # f = open('SIMPLE_PROGRAM.dot', 'w')
    # f.write(cflow.graph.to_dot())
    # f.close()

    # G=pgv.AGraph("SIMPLE_PROGRAM.dot", strict=False, overlap=False, splines='spline')
    # G.layout()
    # G.draw('SIMPLE_PROGRAM.png')
    assert cflow.blocks is not None
    assert len(cflow.dominators.dom) > 0


WHILE_CASE = """
print 'hi'
i = 0
while i < 5:
  h = 3
  if i == 3:
    print i
    i += 1
  print h
print 'end'
"""
def test_while_loop():
  co_simple = get_co(WHILE_CASE)
  assert co_simple is not None

  bytecode_object = BytecodeObject('<string>')
  bytecode_object.parse_code(co_simple)

  assert len(bytecode_object.declarations) == 1

  for decl in bytecode_object.declarations:
    cflow = ControlFlow(decl)

    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('WHILE_PROGRAM.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    # G=pgv.AGraph("WHILE_PROGRAM.dot", strict=False, overlap=False, splines='spline')
    # G.layout()
    # G.draw('WHILE_PROGRAM.png')

    # assert cflow.blocks is not None
    # assert len(cflow.dominators.dom) > 0


USER_PIC = """
def user_pic(request):
    base_path = os.path.join(os.path.dirname(__file__), '../../badguys/static/images')
    filename = request.GET.get('p')

    try:
        data = open(os.path.join(base_path, filename), 'rb').read()
    except IOError:
        if filename.startswith('/'):
            msg = "That was worth trying, but won't always work."
        elif filename.startswith('..'):
            msg = "You're on the right track..."
        else:
            msg = "Keep trying..."
        return render(request, 'vulnerable/injection/file_access.html',
                {'msg': msg})

    return Poop(data, content_type=mimetypes.guess_type(filename)[0])
"""
def test_user_pic():
  co_simple = get_co(USER_PIC)
  assert co_simple is not None

  bytecode_object = BytecodeObject('<string>')
  bytecode_object.parse_code(co_simple)

  assert len(bytecode_object.declarations) == 2

  for decl in bytecode_object.declarations:
    cflow = ControlFlow(decl)

    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)


    f = open('USER_PIC.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()


# IF_STMTS_CASE = """
# if i == 1:
#   print 1
# elif i == 2:
#   print 2
# elif i % 0 == 1:
#   print 'elif'
# else:
#   print 'final-case'
# """

IF_STMTS_CASE = """
i=3
y=i
y=y+1
if i == 1 and i-1==0:
  print 1
elif i == 2:
  print 2
elif i % 1 == 1:
  print 'elif'
else:
  print 'final-case'
redirect(something_else(y))
"""
def test_if_statements():
  co_simple = get_co(IF_STMTS_CASE)
  assert co_simple is not None

  bytecode_object = BytecodeObject('<strhhhhhing>')
  bytecode_object.parse_code(co_simple)

  logger.debug('bytecode_object is ')
  logger.debug(dir(bytecode_object))
  # logger.debug('bytecode_object.bytecode is ')
  # logger.debug(bytecode_object.bytecode)
  logger.debug('bytecode_object.loads is ')
  logger.debug(bytecode_object.loads)
  logger.debug('bytecode_object.stores is ')
  logger.debug(bytecode_object.stores)
  logger.debug('bytecode_object.compares is ')
  logger.debug(bytecode_object.compares)
  logger.debug('bytecode_object.rets is ')
  logger.debug(bytecode_object.rets)

  logger.debug('Finished parsing code\n')
  assert len(bytecode_object.declarations) == 1

  for decl in bytecode_object.declarations:
    cflow = ControlFlow(decl)

    # Print Dominance Frontier
    logger.debug('dominators.frontier is')
    logger.debug(cflow.dominators.frontier)

    # Print Dominators
    # logger.debug('Dominators are')
    # logger.debug('----------------------------')
    # cflow.dominators.print_tree(post_dom=False)
    # logger.debug('----------------------------')

    # Print BasicBlocks
    logger.debug("Blocks in CFG are: ")
    for b in cflow.blocks:
      logger.debug(b)

    # Create IF_STMTS_CASE.png
    f = open('IF_STMTS_CASE.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()
    #G=pgv.AGraph("IF_STMTS_CASE.dot", strict=False, overlap=False, splines='spline')
    #G.layout()
    #G.draw('IF_STMTS_CASE.png')

    assert cflow.blocks is not None
    assert len(cflow.dominators.dom) > 0



LOOP_BREAK_CASE = """
def func():
  while i < length:
    if i % 2 == 0:
      break
    for j in range(0, 10):
      k = 0
      for k in range(0, 10):
        l = 0
        for l in range(0, 10):
          print j, k, l
          if l == 2:
            break
          elif l == 3:
            return
        print "end-l-loop"
        if k == 2:
          break
      print "end-k-loop"
    print "end-j-loop"

  print "Final"
"""
def test_loop_breaks():
  logger.debug("test_loop_breaks")
  co_simple = get_co(LOOP_BREAK_CASE)
  assert co_simple is not None

  bytecode_object = BytecodeObject('<string>')
  bytecode_object.parse_code(co_simple)

  assert len(bytecode_object.declarations) == 2

  for decl in bytecode_object.declarations:
    cflow = ControlFlow(decl)
    assert cflow.blocks is not None
    assert len(cflow.dominators.dom) > 0
