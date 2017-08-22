"""
  junkhacker.bytecode
  ~~~~~~~~~~~~~~

  Operations and representations related to parsing the bytecode
  and extracting its structure.
"""

from .code import BytecodeObject
from .decl import Declaration, \
                  ImportDeclaration, \
                  ModuleDeclaration, \
                  TypeDeclaration, \
                  MethodDeclaration, \
                  FieldDeclaration

