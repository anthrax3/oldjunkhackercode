"""
  junkhacker.visitors.classes
  ~~~~~~~~~~~~~~~~~~~~~~

  Callback the visit method for each encountered class in the program.
"""

class ClassVisitor(object):
  """
    A class visitor that is triggered for all encountered ``TypeDeclaration``.

    Example, listing all types declared in the bytecode::

      class TypeDeclVisitor(ClassVisitor):
        def __init__(self):
          ClassVisitor.__init__(self)

        def visit(self, typeDecl):
          print "New type: %s (parentDecl=%s)" \\
                % (typeDecl.type_name, typeDecl.parent)
  """

  def __init__(self):
    pass

  def visit(self, typeDecl):
    pass
