"""
  junkhacker.analysis.graph.traversals
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  DFS/BFS and some other utils
"""

from ...utils.log import logger
from .graphs import Edge

import uuid

class EdgeVisitor(object):
  def __init__(self):
    pass

  def visit(self, edge):
    pass


class Walker(object):
  """
    Traverses edges in the graph in DFS.
  """
  def __init__(self, graph, visitor, backwards=False):
    self.graph = graph
    self.visitor = visitor
    self._backwards = backwards
    self.worklist = None

  def traverse(self, root):
    self.worklist = []
    self.__run(root)

  def __run(self, root=None):
    visited = set()
    if root is not None:
      self.__process(root)
    while self.worklist:

      logger.debug('visited is')
      logger.debug(visited)

      current = self.worklist.pop(0)
      if current in visited:
        continue
      self.__process(current)
      visited.add(current)

  def __process(self, current):
    cur_node = None
    if isinstance(current, Edge):
      cur_node = current.dest if not self._backwards else current.source
      self.visitor.visit(current)
    else:
      cur_node = current

    list_edges = self.graph.out_edges(cur_node)     \
                 if not self._backwards             \
                 else self.graph.in_edges(cur_node)
    for edge in list_edges:
      self.worklist.insert(0, edge)


# Recursive version of the post-order DFS, should only be used
# when computing dominators on smallish CFGs
def dfs_postorder_nodes(graph, root):
  import sys
  sys.setrecursionlimit(500)
  visited = set()

  def _dfs(node, _visited):
    _visited.add(node)
    # For each child
    for edge in graph.out_edges(node):
      dest_node = edge.dest
      # If it's not in _visited yet
      if dest_node not in _visited:
        # Call _dfs on it
        for child in _dfs(dest_node, _visited):
          yield child
    yield node

  # We pass the root and an empty set
  return [n for n in _dfs(root, visited)]



class Queue:
  def __init__(self):
    self.items = []

  def isEmpty(self):
    return self.items == []

  def enqueue(self, item):
    self.items.insert(0,item)

  def dequeue(self):
    return self.items.pop()

  def size(self):
    return len(self.items)

def bfs_set_buddies(graph, root):
  """
  Marks each divergence node with it's "Buddy", using a BFS traversal and shards to keep track of things

  xrefs to UUIDs:
    Inheritence
    If the parent splits

    & of course. setting the buddy

  node.visited_from is a set that we add the incoming node GID to, so that loops don't fuck things up.

  (Not really BFS anymore, because we can repeat when updates happen. But similar in nature.)
  """
  assert root.kind == 'ENTRY'

  logger.debug("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nINITIATE BUDDY SYSTEM")
  logger.debug("Graph is %s", graph)
  logger.debug("Root is %s", root)

  for node in graph.nodes:
    node.visited_from = set()
    logger.debug("node is %s", node)
    logger.debug("graph.out_edges(node) is %s", graph.out_edges(node))
    for out_edge in graph.out_edges(node):
      logger.debug("type(out_edge) == %s", type(out_edge))

  bfsQ = Queue()
  bfsQ.enqueue(root)
  foo = 0
  logger.warn("OUTSIDE WHAT THE FUCK Okay so this is the Nth time this has ran %s", foo)
  while not bfsQ.isEmpty():
      foo = foo+1
      current = bfsQ.dequeue()
      logger.warn("Okay so this is the Nth time this has ran %s Current is %s", foo, current.data.p_range())

      logger.debug("FFFCurrent.data.p_range() is %s", current.data.p_range())
      # logger.debug('current.uuids are %s', current.uuids)
      logger.debug('len(current.uuids) are %s', len(current.uuids))
      # logger.debug("Current type(node) is %s", type(current))
      logger.debug("Current node children = %s", graph.out_edges(current))
      # logger.debug("Current node parents = %s", graph.in_edges(current))

      # Code for setting buddies!
      if len(current.uuids) > 0:# and current.buddy is None:
        logger.debug("Okay let's see if we can add a buddy!")

        # Iterate over a copy of the set, while removing items from the original.
        copy_of_uuids = current.uuids.copy()
        logger.debug("CURRENT NODE IS %s", current.data.p_range())
        for node, shards in copy_of_uuids.iteritems():
          # logger.debug("node is %s", node)
          # logger.debug("nodeyyy is %s", node.data.p_range())
          logger.debug("[kevin]# of uuids for %s is %s", node.data.p_range(), len(copy_of_uuids[node]))
          total = 0
          previously_seen = set()
          if shards != 'No more':
            for single_shard in shards:
                if single_shard.uuid_ not in previously_seen:
                  # logger.warn("So the single_shard.node is %s", single_shard.node)
                  previously_seen.add(single_shard.uuid_)
                  total = total + single_shard.value
          logger.debug("the total is %s", total)
          if total > 1.0:
            logger.error("Alright something is wrong!")
            raise
          if total == 1.0:
            if node.buddy is not None:
              logger.error("So I already got a buddy")
              logger.error("I am %s and my buddy is %s, fuck %s", node.data.p_range(), node.buddy.data.p_range(), current.data.p_range())
              current.uuids[node] = 'No more'
            else:
              # They're all here! Set the buddy
              node.buddy = current
              node.data.buddy = current.data

              # Let's remove the right UUIDs
              current.uuids[node] = 'No more'

              logger.error("Okay we did it, let's set the buddy")
              # logger.error("current.uuids[node] is %s", current.uuids[node])


      children_nodes = set()
      # Root at first
      for out_edge in graph.out_edges(current):
        children_nodes.add(out_edge.dest)
      logger.debug("children_nodes are %s", children_nodes)

      # Here we set a flag if one child is a return block and the other is not, so that we can give all UUIDs to the one that is not. e.g.
      # if law and not briscoe:
      #     return guilty(law)
      # self.redirect(infected)
      # law and briscoe can have redirect be there buddy now
      best_child = -1
      if len(children_nodes) == 2:
        first_child = children_nodes.pop()
        second_child = children_nodes.pop()
        if first_child.data.has_return_value and not second_child.data.has_return_value:
          best_child = 1
        if not first_child.data.has_return_value and second_child.data.has_return_value:
          best_child = 0
        children_nodes.add(first_child)
        children_nodes.add(second_child)

      # This loop can only run max 2 times (0, 1)
      for i, child in enumerate(children_nodes):
          assert len(children_nodes) == 1 or len(children_nodes) == 2
          logger.debug("START node %s", current.data.p_range())
          logger.debug("i is %s and child is %s", i, child)
          logger.debug('# of kids is %s', len(children_nodes))

          unique_path = 'Parent:'+ str(current.data.p_range()) + ' Child:'+ str(child.data.p_range()) +' UUIDs:'+ str(current.uuids)
          logger.info("helpful unique_path is %s", unique_path)
          # Create a copy of UUIDs and remove the current node,
          #   so that the root of a loop doesn't count it's own UUIDs
          #   and go on forever thinking something changed.
          copy_of_uuids = current.uuids.copy().pop(current, None)
          unique_path = 'Parent:'+ str(current.data.p_range()) +' UUIDs:'+ str(copy_of_uuids)
          logger.info("actual unique_path is %s", unique_path)

          if unique_path not in child.visited_from:
              child.visited_from.add(unique_path)

              if len(children_nodes) == 1:
                # Give the only child their parents' UUIDS
                for node, shards in current.uuids.iteritems():
                  if node not in child.uuids.keys():
                    child.uuids[node] = []
                  if shards != 'No more' and child.uuids[node] != 'No more':
                    # Fill in the empty ones with an empty list
                    # logger.warn("shards is %s", shards)
                    # logger.warn("child.uuids[node] is %s", child.uuids[node])
                    assert type(shards) == type(child.uuids[node])
                    logger.debug("single_child is %s", child.data.p_range())
                    # logger.info("[single_child] before child.uuids[node] is %s", child.uuids[node])
                    child.uuids[node] = extend_first_without_dupes(child.uuids[node], shards)

                    # logger.info("[single_child] after child.uuids[node] is %s", child.uuids[node])
              elif len(children_nodes) == 2:
                for node, shards in current.uuids.iteritems():
                  logger.debug("has_return_value of %s is %s", child.data.p_range(), child.data.has_return_value)
                  if shards != 'No more':
                    for single_shard in shards:
                        # Split uuids into uuid first half, and uuid second half
                        if current.gid not in single_shard.second_time_around:
                          left, right = single_shard.split(current)
                          give_left_or_right_to_kid(i, node, child, left, right, best_child)
                # We give a shard of ourselves to each child
                if current.never_split_before < 2:
                  current.never_split_before = current.never_split_before + 1
                  left, right = shard(current).split(current)
                  give_left_or_right_to_kid(i, current, child, left, right, best_child)
                  logger.debug("So this is child #%s", i)

              # if current.uuids:
              #   logger.debug("So we added %s to child %s", current.uuids, child)
                # logger.debug("current uuids are %s", current.uuids)
                # logger.debug("Child uuids are %s", child.uuids)

              # Add kid to the queue!
              bfsQ.enqueue(child)

              logger.debug("Current node children = %s", graph.out_edges(current))
              logger.debug("Child is now %s", child)
          else:
              logger.debug("The child %s is already visited so I'm not adding uuids", child)

def extend_first_without_dupes(first_list, second_list):
  in_first = set(first_list)
  in_second = set(second_list)

  in_second_but_not_in_first = in_second - in_first

  result = first_list + list(in_second_but_not_in_first)
  return result

class shard(object):
  """Used exclusively for bfs_set_buddies"""
  def __init__(self, node, value=1.0):
    self.node = node
    self.value = value
    self.uuid_ = uuid.uuid4()
    self.first_time_around = set()
    self.second_time_around = set()

  def __repr__(self):
    return "("+str(self.value)+", "+str(self.uuid_)+")"

  def split(self, current):
    if current.gid in self.first_time_around:
      self.second_time_around.add(current.gid)
    if current.gid not in self.first_time_around:
      self.first_time_around.add(current.gid)
    left = shard(self.node, self.value/2)
    right = shard(self.node, self.value/2)
    return left, right

def give_left_or_right_to_kid(i, node, child, left, right, best_child):
  if node not in child.uuids.keys():
    child.uuids[node] = []
  # logger.debug("[give_left_or_right_to_kid] node is %s, kid is %s", node.data.p_range(), child.data.p_range())
  # Give all UUIDs to the other kid if this one has a return
  if i == 0:
    # logger.debug("[left_child]before child.uuids[node] is %s", child.uuids[node])
    if best_child < 1:
      child.uuids[node] = extend_first_without_dupes(child.uuids[node], [left])
    if best_child == 0:
      child.uuids[node] = extend_first_without_dupes(child.uuids[node], [right])
    # logger.debug("[left_child]after child.uuids[node] is %s", child.uuids[node])
  elif i == 1:
    # logger.debug("[right_child]before child.uuids[node] is %s", child.uuids[node])
    # Note: best_child can be -1, 0 or 1
    if best_child != 0:
      child.uuids[node] = extend_first_without_dupes(child.uuids[node], [right])
    if best_child == 1:
      child.uuids[node] = extend_first_without_dupes(child.uuids[node], [left])
    # logger.debug("[right_child]after child.uuids[node] is %s", child.uuids[node])
