"""
  junkhacker.visitors
  ~~~~~~~~~~~~~~

  Different visitor interfaces to traverse the bytecode, modules,
  classes, or methods.
"""
from .bytecode import BytecodeVisitor
from .classes import ClassVisitor
from .methods import MethodVisitor
from .modules import ModuleVisitor
