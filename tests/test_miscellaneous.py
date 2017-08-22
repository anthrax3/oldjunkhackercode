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

BAD_IMPORTS =("xml.etree.ElementTree",
  "xml.dom",
  "xml.dom.minidom",
  "xml.dom.pulldom",
  "xml.sax",
  "xml.parsers.expat",
  "import md5",
  "import sha1",
  "import sha")

def test_left_foo_on_stack_due_to_conditional():
  """

  """
  f = open("files_to_test_against/left_foo_on_stack_due_to_conditional.py")
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

    # We can't just pass root in -- the stack, environment etc. will progagate otherwise.
    if decl.kind == Declaration.METHOD:
      cflow.taint_propagation(cflow.root, tainted=set(decl.formal_parameters), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')
    else:
      cflow.taint_propagation(cflow.root, tainted=set(), stack=[], environment={}, immune={}, previous_edges=set(), new_edge='')

    # logger.debug('dominators.frontier is')
    # logger.debug(cflow.dominators.frontier)

    f = open('VIEWS'+str(x)+'.dot', 'w')
    f.write(cflow.graph.to_dot())
    f.close()

    G=pgv.AGraph('VIEWS'+str(x)+'.dot', strict=False, overlap=False, splines='spline')
    G.layout()
    G.draw('VIEWS'+str(x)+'.png')
    x = x+1

  # assert
  with open("junkhacker.log.py") as log_file:
    logs = log_file.read()
    assert "Cleaning a leftover *const_foo due to a JUMP_IF_TRUE_OR_POP instruction at edge 0->36" in logs
    assert logs.count("Cleaning a leftover") == 1


def test_kwargs():
  """

  """
  f = open("files_to_test_against/kwargs.py")
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

    kwargs = {'*const_user': 'return value of "(\'Alice.me\', [], {})"', '*const_consumer': 'consumer', '*const_fast': 'fast'}
    key_string = "type(kwargs) is <class 'junkhacker.analysis.basicBlockInterpreter.kdict'> and kwargs is "+str(kwargs)

    assert key_string in logs
    assert logs.count(key_string) == 1


def test_tryexcept():
  """

  """
  # Part 1
  f = open("files_to_test_against/tryexcept.py")
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

  # with open("junkhacker.log.py") as log_file:
  #   logs = log_file.read()
  #   there_was_an_error = "Traceback"
  #   assert logs.count(there_was_an_error) == 0

  # Part 2
  f = open("files_to_test_against/tryexceptexception.py")
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

    returning = ") - returning "

    return_value0 = str([{'*const_message': '*const_Yo'}])
    key_string0 = returning + return_value0
    assert logs.count(key_string0) == 6

    return_value1 = str(['*const_None'])
    key_string1 = returning + return_value1
    assert logs.count(key_string1) == 2

    return_value2 = str([{'*const_message': '*const_success'}])
    key_string2 = returning + return_value2
    # Why 5? Why tryexcept 2 + tryexceptexception 3? Oh well.
    assert logs.count(key_string2) == 5

    return_value3 = str([{'*const_message': '*const_Failed'}])
    key_string3 = returning + return_value3
    assert logs.count(key_string3) == 2




# CODE_EXECUTION = """
# def code_execution(request):
#     data = ''
#     msg = ''
#     first_name = ''
#     if request.method == 'POST':

#         # Clear out a previous success to reset the exercise
#         try:
#             os.unlink('p0wned.txt')
#         except:
#             pass

#         first_name = request.POST.get('first_name', '')

#         try:
#             # Try it the Python 3 way...
#             exec(base64.decodestring(bytes(first_name, 'ascii')))
#         except TypeError:
#             # Try it the Python 2 way...
#             try:
#                 exec(base64.decodestring(first_name))
#             except:
#                 pass
#         except:
#             pass

#         # Check to see if the attack was successful
#         try:
#             data = open('p0wned.txt').read()
#         except IOError:
#             data = ''

#     ghi = {'first_name': request.POST.get('first_name', ''), 'data': data}

#     return render(request, 'vulnerable/injection/code_execution.html', ghi)
# """

# def test_code_execution():
#   co_simple = get_co(CODE_EXECUTION)
#   assert co_simple is not None

#   bytecode_object = BytecodeObject('<string>')
#   bytecode_object.parse_code(co_simple)

#   assert len(bytecode_object.declarations) == 2

#   for decl in bytecode_object.declarations:

#     if decl.kind == Declaration.METHOD:
#       logger.debug('decl.formal_parameters is')
#       logger.debug(decl.formal_parameters)

#     cflow = ControlFlow(decl)

#     # Print BasicBlocks
#     logger.debug("Blocks in CFG are: ")
#     for b in cflow.blocks:
#       logger.debug(b)

#     logger.debug('dominators.frontier is')
#     logger.debug(cflow.dominators.frontier)


#     f = open('CODE_EXECUTION.dot', 'w')
#     f.write(cflow.graph.to_dot())
#     f.close()
#     assert 1 == 0







# Dont work on the one below
# Dont work on the one below
# Dont work on the one below
# Dont work on the one below
# Dont work on the one below
# def test_imports():
#   f = open("")
#   source = f.read()

#   logger.debug('source is')
#   logger.debug(source)

#   bytecode_object = BytecodeObject('<string>')
#   compiled_code = get_co(source)
#   bytecode_object.parse_code(compiled_code)

#   logger.debug('ghi declarations are')
#   logger.debug(bytecode_object.declarations)
#   # logger.debug('ghi dir(bytecode_object) is')
#   # logger.debug(dir(bytecode_object))
#   logger.debug('bytecode_object.main_module is')
#   logger.debug(bytecode_object.main_module)
#   for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
#     logger.debug('imp_stmt is')
#     logger.debug(imp_stmt)
#     if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
#       logger.debug("EMERGENCY")

# def test_import_dot_this_and_that():
#   f = open("")
#   source = f.read()

#   logger.debug('source is')
#   logger.debug(source)

#   bytecode_object = BytecodeObject('<string>')
#   compiled_code = get_co(source)
#   bytecode_object.parse_code(compiled_code)

#   logger.debug('ghi declarations are')
#   logger.debug(bytecode_object.declarations)
#   # logger.debug('ghi dir(bytecode_object) is')
#   # logger.debug(dir(bytecode_object))
#   logger.debug('bytecode_object.main_module is')
#   logger.debug(bytecode_object.main_module)
#   for imp_stmt in bytecode_object.main_module.imports: #enumerate tktk
#     logger.debug('imp_stmt is')
#     logger.debug(imp_stmt)
#     if any(bad_imp in str(imp_stmt) for bad_imp in BAD_IMPORTS):
#       logger.debug("EMERGENCY")
#   for decl in bytecode_object.declarations:
#     # logger.debug('decl.formal_parameters is')
#     # logger.debug(decl.formal_parameters)
#     logger.debug('decl.kind is')
#     logger.debug(decl.kind)
#     if decl.kind == Declaration.METHOD:
#       logger.debug('decl.formal_parameters is')
#       logger.debug(decl.formal_parameters)
#     logger.debug('dir(decl) is')
#     logger.debug(dir(decl))
#     cflow = ControlFlow(decl)

#     # Print BasicBlocks
#     logger.debug("Blocks in CFG are: ")
#     for b in cflow.blocks:
#       logger.debug(b)

#     logger.debug('dominators.frontier is')
#     logger.debug(cflow.dominators.frontier)
