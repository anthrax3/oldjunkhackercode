"""
  junkhacker.analysis.graph.dominators
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  Dominator tree
"""

from ...utils.log import logger
from .graphs import DiGraph, Node, Edge
from .traversals import dfs_postorder_nodes
# import pygraphviz as pgv


class DominatorTree(object):
  """
    Handles the dominator trees (dominator/post-dominator), and the
    computation of the dominance frontier.
  """
  def __init__(self, cfg):
    self.cfg = cfg
    self.dom = {}
    # Maps each node to its immediate post-dominator.
    self.post_dom = {}
    # Maps each node to its dominance frontier (a set).
    self.frontier = {}
    self.rpo = {}
    # RPO of the inverted graph
    self.rpoi = {}
    self.build()

  def build(self):
    try:
      graph = self.cfg.graph
      entry = self.cfg.entry_node
      exit = self.cfg.exit_node

      # Inverse the CFG to compute the post dominators using the same algo
      inverted_graph = graph.inverse()

      self.__build_dominators(graph, entry, post_dom=False)
      self.__build_dominators(inverted_graph, exit, post_dom=True)
      self.__build_rpo(inverted_graph, exit, inverted=True)
      self.__build_rpo(graph, entry, inverted=False)
      # try:
      self.__build_df()
      # except KeyError:
      #   logger.debug("It's okay")
    except Exception, ex:
      logger.error("Exception %s", repr(ex), exc_info=ex)
      raise

  def __build_rpo(self, graph, entry, inverted=False):
    reverse_post_order = list(reversed(dfs_postorder_nodes(graph, entry)))
    if inverted:
      self.rpoi = reverse_post_order
    else:
      self.rpo = reverse_post_order

  def __build_dominators(self, graph, entry, post_dom=False):
    """
      Builds the dominator tree based on:
        http://www.cs.rice.edu/~keith/Embed/dom.pdf

      Also used to build the post-dominator tree.
    """
    doms = self.dom if not post_dom else self.post_dom
    doms[entry] = entry
    logger.debug("[issue#2] graph is %s", graph)

    for node in graph.nodes:
      logger.debug("Node is %s", node)
    logger.debug("multiple_edges is %s", graph.multiple_edges)
    for edge in graph.edges:
      logger.debug("Edge is %s", edge)

    logger.debug("[issue#2] entry is %s", entry)
    post_order = dfs_postorder_nodes(graph, entry)
    logger.debug("len(graph.nodes) is %s", len(graph.nodes))
    logger.debug("Well well well, the len(post_order) is %s", len(post_order))
    logger.debug("Well well well, the post_order is %s", post_order)
    logger.debug("Well well well, the graph.nodes is %s", graph.nodes)
    post_order_number = {}
    i = 0
    for n in post_order:
      post_order_number[n] = i
      i += 1

    def intersec(b1, b2):
      finger1 = b1
      finger2 = b2
      try:
        po_finger1 = post_order_number[finger1]
      except KeyError:
        logger.debug("finger1 is %s", finger1)
        logger.debug("post_order_number is %s", post_order_number)
        raise
      try:
        po_finger2 = post_order_number[finger2]
      except KeyError:
        logger.debug("finger2 is %s", finger2)
        logger.debug("post_order_number is %s", post_order_number)
        raise
      while po_finger1 != po_finger2:
        no_solution = False
        while po_finger1 < po_finger2:
          finger1 = doms.get(finger1, None)
          if finger1 is None:
            no_solution = True
            break
          po_finger1 = post_order_number[finger1]
        while po_finger2 < po_finger1:
          finger2 = doms.get(finger2, None)
          if finger2 is None:
            no_solution = True
            break
          po_finger2 = post_order_number[finger2]
        if no_solution:
          break
      return finger1

    i = 0
    changed = True
    while changed:
      i += 1
      changed = False
      for b in reversed(post_order):
        if b == entry:
          continue
        predecessors = graph.in_edges(b)
        new_idom = next(iter(predecessors)).source
        for p_edge in predecessors:
          p = p_edge.source
          if p == new_idom:
            continue
          if p in doms:
            if new_idom not in post_order_number:
              logger.debug("Well fuck me, bytecode sucks. new_idom is %s", new_idom)
              continue
            else:
              new_idom = intersec(p, new_idom)
        if b not in doms or doms[b] != new_idom:
          if new_idom not in post_order_number:
            logger.debug("WELL FUCK new_idom is %s", new_idom)
          # else:
          doms[b] = new_idom
          changed = True
    # self.print_tree(post_dom)

  def __build_df(self):
    """
      Builds the dominance frontier.
    """
    graph = self.cfg.graph
    entry = self.cfg.entry_node

    self.frontier = {}
    for b in graph.nodes:
      self.frontier[b] = set()

    for b in graph.nodes:
      predecessors = graph.in_edges(b)
      if len(predecessors) > 1:
        for p_edge in predecessors:
          p = p_edge.source
          runner = p
          while runner != self.dom[b]:
            self.frontier[runner].add(b)
            # logger.debug("self.dom is %s", self.dom)
            # logger.debug("lol b is %s", b)
            # logger.debug("lol p is %s", p)
            # logger.debug("lol p_edge is %s", p_edge)
            # logger.debug("predecessors are %s", predecessors)
            logger.debug("self.dom are %s", self.dom)
            logger.debug("before runner is %s", runner)
            try:
              runner = self.dom[runner]
            except KeyError:
              break
            logger.debug("after runner is %s", runner)


  def print_tree(self, post_dom=False):
    g_nodes = {}
    doms = self.dom if not post_dom else self.post_dom
    g = DiGraph()

    for node in doms:
      if node not in g_nodes:
        cur_node = g.make_add_node(data=node)
        g_nodes[node] = cur_node
      cur_node = g_nodes[node]

      parent = doms.get(node, None)
      if parent is not None and parent != node:
        if parent not in g_nodes:
          parent_node = g.make_add_node(data=parent)
          g_nodes[parent] = parent_node
        parent_node = g_nodes[parent]
        g.make_add_edge(parent_node, cur_node)
# Debug stuff
    # logger.debug("%sDOM-tree :=\n%s", 'POST-' if post_dom else '', g.to_dot())
    # f = open('DOMINIQUE.dot', 'w')
    # f.write(g.to_dot())
    # f.close()
    # G=pgv.AGraph("DOMINIQUE.dot", strict=False, overlap=False, splines='spline')
    # G.layout()
    # G.draw('DOMINIQUE.png')

