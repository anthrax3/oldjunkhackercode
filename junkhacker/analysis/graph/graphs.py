"""
  junkhacker.analysis.graph.graphs
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~

  Graph data structures
"""
import copy
from ...utils.log import logger

class Node(object):
  GLOBAL_COUNTER = 0

  def __init__(self, kind=None, data=None):
    Node.GLOBAL_COUNTER += 1
    self.gid = Node.GLOBAL_COUNTER
    self.kind = kind
    self.data = data
    self.buddy = None
    self.never_split_before = 0
    self.uuids = {}

  def __eq__(self, obj):
    return isinstance(obj, Node) and obj.gid == self.gid

  def __hash__(self):
    return hash(self.gid)

  def __repr__(self):
    # return 'Node%d(kind=%s, uuids=%s, buddy=%s, data=%s)' % (self.gid, repr(self.kind), self.uuids, self.buddy, repr(self.data))
    if self.buddy:
      return 'Node%d(kind=%s, buddy=%s, data=%s)' % (self.gid, repr(self.kind), self.buddy.data.p_range(), repr(self.data))
    else:
      return 'Node%d(kind=%s, data=%s)' % (self.gid, repr(self.kind), repr(self.data))


class Edge(object):
  GLOBAL_COUNTER = 0

  def __init__(self, source=None, dest=None, kind=None, data=None):
    Edge.GLOBAL_COUNTER += 1
    self.gid = Edge.GLOBAL_COUNTER
    self.source = source
    self.dest = dest
    self.kind = kind
    self.data = data
    self.inversed = False

  def inverse(self):
    tmp = self.source
    self.source = self.dest
    self.dest = tmp
    self.inversed = True

  def __eq__(self, obj):
    return isinstance(obj, Edge) and obj.gid == self.gid

  def __hash__(self):
    return hash(self.gid)

  def __repr__(self):
    return 'Edge%d(source=%s, dest=%s, kind=%s, data=%s)' \
           % (self.gid, self.source, self.dest, repr(self.kind), repr(self.data))



class DiGraph(object):
  """
    A simple directed-graph structure.
  """

  def __init__(self, multiple_edges=True):
    self.multiple_edges = multiple_edges
    self.nodes = set()
    self.edges = set()
    self._in = {}
    self._out = {}

  def add_edge(self, edge):
    if edge in self.edges:
      raise Exception('Edge already present')
    source_node, dest_node = edge.source, edge.dest

    if not self.multiple_edges:
      # If we already connected src and dest, return
      if source_node in self._out and dest_node in self._out[source_node]:
        logger.error("Already connected nodes: %s", edge)
        return
      if dest_node in self._in and source_node in self._in[dest_node]:
        logger.error("Already connected nodes: %s", edge)
        return

    self.edges.add(edge)
    self.add_node(source_node)
    self.add_node(dest_node)
    DiGraph.__add_edge(self._out, source_node, dest_node, edge)
    DiGraph.__add_edge(self._in, dest_node, source_node, edge)

  def remove_edge(self, edge):
    if edge not in self.edges:
      return
    source_node, dest_node = edge.source, edge.dest
    DiGraph.__remove_edge(self._out, source_node, dest_node, edge)
    DiGraph.__remove_edge(self._in, dest_node, source_node, edge)
    self.edges.remove(edge)

  @staticmethod
  def __add_edge(in_out, source, dest, edge):
    if source not in in_out:
      in_out[source] = {}
    if dest not in in_out[source]:
      in_out[source][dest] = set()
    in_out[source][dest].add(edge)

  @staticmethod
  def __remove_edge(in_out, source, dest, edge):
    if source not in in_out:
      return
    if dest not in in_out[source]:
      return
    if edge in in_out[source][dest]:
      in_out[source][dest].remove(edge)
    if not in_out[source][dest]:
      in_out[source].pop(dest, None)
    if not in_out[source]:
      in_out.pop(source, None)

  def has_node(self, node):
    if not isinstance(node, Node):
      logger.debug("WRONG TYPE passed to has_node")
      raise
    return node in self.nodes

  def add_node(self, node):
    self.nodes.add(node)

  def remove_node(self, node):
    if node not in self.nodes:
      return
    # Remove all edges that touched this node
    self.edges = set([e for e in self.edges if e.source != node and e.dest != node])
    # Clean up _in/_out
    for src in self._in:
      self._in[src].pop(node, None)
    for dest in self._out:
      self._out[dest].pop(node, None)
    if node in self._in:
      self._in.pop(node, None)
    if node in self._out:
      self._out.pop(node, None)
    # Finally remove the node
    self.nodes.remove(node)

  def in_edges(self, node):
    if not self.has_node(node) or node not in self._in:
      return set()
    return set([e for n in self._in[node] for e in self._in[node][n]])

  def out_edges(self, node):
    if not self.has_node(node) or node not in self._out:
      return set()
    return set([e for n in self._out[node] for e in self._out[node][n]])

  def in_degree(self, node):
    return len(self.in_edges(node))

  def roots(self):
    r = set()
    for n in self.nodes:
      if self.in_degree(n) < 1:
        r.add(n)
    return r

  def out_degree(self, node):
    return len(self.out_edges(node))

  def to_dot(self):
    from .io import DotConverter
    return DotConverter.process(self)

  # Some helpers
  def make_add_node(self, kind=None, data=None):
    node = DiGraph.make_node(kind=kind, data=data)
    self.add_node(node)
    return node

  def make_add_edge(self, source=None, dest=None, kind=None, data=None):
    edge = DiGraph.make_edge(source=source, dest=dest, kind=kind, data=data)
    self.add_edge(edge)
    return edge

  def inverse(self):
    """
      Returns a copy of this graph where all edges have been reversed
    """
    new_g = DiGraph(multiple_edges=self.multiple_edges)
    for edge in self.edges:
      new_edge = copy.deepcopy(edge)
      new_edge.inverse()
      new_g.add_edge(new_edge)
    return new_g

  @staticmethod
  def make_node(kind=None, data=None):
    return Node(kind=kind, data=data)

  @staticmethod
  def make_edge(source=None, dest=None, kind=None, data=None):
    return Edge(source=source, dest=dest, kind=kind, data=data)

  def __repr__(self):
    return 'Digraph(nodes=%s, edges=%s)' \
           % (self.nodes, repr(self.edges))

    # return 'Digraph%d(src=%s, dst=%s, kind=%s, data=%s)' \
    #        % (self.gid, self.source, self.dest, repr(self.kind), repr(self.data))
