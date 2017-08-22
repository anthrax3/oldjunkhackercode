"""
  junkhacker.visitors.methods
  ~~~~~~~~~~~~~~~~~~~~~~

  Callback the visit method for each encountered method in the program.
"""

class MethodVisitor(object):
  """
    A method visitor that is triggered for all encountered ``MethodDeclaration``.

    Example, listing all methods declared in the bytecode::

      class MethodDeclVisitor(MethodVisitor):
        def __init__(self):
          MethodVisitor.__init__(self)

        def visit(self, methDecl):
          print "New method: %s:%d (parentDecl=%s)" \\
                % (methDecl.method_name, methDecl.start_lineno, methDecl.parent)
  """
  def __init__(self):
    pass

  def visit(self, methodDecl):
    pass
