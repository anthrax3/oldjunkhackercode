A
  2(  0)          LOAD_GLOBAL(116) ('iced')
  2(  3)            LOAD_ATTR(106) ('me')
  2(  6)        CALL_FUNCTION(131) (0)
  2(  9)          LOAD_GLOBAL(116) ('c')
  2( 12)           STORE_ATTR( 95) ('iced')
  3( 15)          LOAD_GLOBAL(116) ('c')
  3( 18)            LOAD_ATTR(106) ('iced')
  3( 21)            LOAD_ATTR(106) ('foo')
  3( 24)          LOAD_GLOBAL(116) ('c')
  3( 27)           STORE_ATTR( 95) ('foo')
  4( 30)          LOAD_GLOBAL(116) ('secure_get_next_url')
  4( 33)          LOAD_GLOBAL(116) ('request')
  4( 36)            LOAD_ATTR(106) ('params')
  4( 39)            LOAD_ATTR(106) ('get')
  4( 42)           LOAD_CONST(100) ('next')
  4( 45)        CALL_FUNCTION(131) (1)
  4( 48)        CALL_FUNCTION(131) (1)
  4( 51)          LOAD_GLOBAL(116) ('c')
  4( 54)           STORE_ATTR( 95) ('next')
  6( 57)          LOAD_GLOBAL(116) ('c')
  6( 60)            LOAD_ATTR(106) ('iced')
  6( 63)            LOAD_ATTR(106) ('spring')
  6( 66)            LOAD_ATTR(106) ('id')
  6( 69)          LOAD_GLOBAL(116) ('c')
  6( 72)           STORE_ATTR( 95) ('star')
  7( 75)           SETUP_LOOP(120) (54) -------------> (132)

B
  7( 78)          LOAD_GLOBAL(116) ('c')
  7( 81)            LOAD_ATTR(106) ('foo')
  7( 84)             GET_ITER( 68)

C
  7( 85)             FOR_ITER( 93) (43) -------------> (131)

D
  7( 88)           STORE_FAST(125) ('h')
  8( 91)          LOAD_GLOBAL(116) ('c')
  8( 94)            LOAD_ATTR(106) ('star')
  8( 97)    POP_JUMP_IF_FALSE(114) (109) -------------> (109)

E
  8(100)          LOAD_GLOBAL(116) ('c')
  8(103)            LOAD_ATTR(106) ('next')
  8(106)         JUMP_FORWARD(110) (3) -------------> (112)

F
  8(109)          LOAD_GLOBAL(116) ('True')

G
  8(112)           STORE_FAST(125) ('bucks')
  9(115)          LOAD_GLOBAL(116) ('water')
  9(118)            LOAD_FAST(124) ('bucks')
  9(121)        BINARY_SUBSCR( 25)
  9(122)            LOAD_FAST(124) ('h')
  9(125)           STORE_ATTR( 95) ('poland')
  9(128)        JUMP_ABSOLUTE(113) (85) -------------> ( 85)

H
  9(131)            POP_BLOCK( 87)

I
 10(132)          LOAD_GLOBAL(116) ('render')
 10(135)           LOAD_CONST(100) ('/dotdot')
 10(138)        CALL_FUNCTION(131) (1)

This repeats for ever
G -> C ...
(112,130) -> (85,87)

      `if c.star`
Should D have the buddy G?
                      `bucks, h.poland = water[bucks]`
def picky(self):
    c.iced = iced.me()
    c.foo = c.iced.foo
    c.next = secure_get_next_url(request.params.get('next'))

    c.star = c.iced.spring.id
    for h in c.foo:
        bucks = c.next if c.star else True
        h.poland = water[bucks]
    return render('/dotdot')

Because the UUIDs for (85,87) will always be different! :D
Well shit

printing unique_path is
    Parent:(131->131)
    Child:(132->138)

printing unique_path is
    Parent:(88->99)
    Child:(100->108)

printing unique_path is
    Parent:(88->99)
    Child:(109->111)

printing unique_path is
    Parent:(132->138)
    Child:(-1->-1)

printing unique_path is
    Parent:(100->108)
    Child:(112->130)

printing unique_path is
    Parent:(109->111)
    Child:(112->130)

printing unique_path is
    Parent:(112->130)
    Child:(85->87)

printing unique_path is
    Parent:(112->130)
    Child:(85->87)

printing unique_path is
    Parent:(85->87)
    Child:(131->131)

printing unique_path is
    Parent:(85->87)
    Child:(88->99)

def picky(self):
    c.iced = iced.me()
    c.foo = c.iced.foo
    c.next = secure_get_next_url(request.params.get('next'))

    c.star = c.iced.spring.id
    for h in c.foo:
        bucks = c.next if c.star else True
        h.poland = water[bucks]
    return render('/dotdot')




python -m pytest test_controllers.py::TestBuddySystem::test_buddy_system_on_or

Create a Destructor that clears "junkhacker.log.py" at the end of every tests so that the assert .count still pass

TODO LIST
        Basic Intraprocedural
              Buddy system :(
                with return test
                DONE multiple consecutive if statements test (it was caused by a 2nd buddy overwriting the 1st buddy)
              tainted_by
                TypeError: 'seq_index' object is not iterable
              -----------------------------------------------------------------------------
        Interprocedural
              Part 5:
                      Pick something from "Answer Q's"
              Answers Q's:
                      After "Write a command-line interface, steal from Bandit" to handle directories, then:
                          How should we handle imports?
                          How do we make sure we analze/dis everything in the right order? :(
                          How should we handle dynamic imports?
                      What if callee_tainted_arg is a dictionary?
                      What if return value is a dictionary?
              I need a local and global environment
              Maybe the hierarchy will be: ModuleDeclaration's(TypeDeclaration's(TypeDeclaration's FieldDeclaration's ImportDeclaration's MethodDeclaration's)  MethodDeclaration's(ImportDeclaration's))
              ImportDeclaration's
                    - Absolute
                    - Relatives
                    - Aliases
              Handle predicates guarded by default bools e.g. some_mode=False if some_mode: sink
              -----------------------------------------------------------------------------
              Write a test for byte_SETUP_LOOP
              Write a test for byte_STORE_SUBSCR
              posargs AND namedargs in # Perform taint check
              Write a test for posargs AND namedargs
              Write a test for byte_EXEC_STMT
              Write a test for byte_SETUP_WITH
        Miscellaneous
              Make a base test to inherit from!

              Fix this
                      # if val in self.tainted:
                      #     self.tainted.add(map_and_key)
                      # else:
                      #     if map_and_key in self.tainted:
                      #         self.tainted.remove(map_and_key)
              Fix this
                I do not know what to do about tainted_by when it comes to slicey and seq_index :O

              Get LOWS and sinks from the same place BasicBlockInterpreter does + blacklists/ directory
              If this is a tainted arg e.g. "c.next = request.params.get('next')", say request.params.get('next') is the arg, not c.next.
              What the hell am I gonna do with the formatters/ directory? :/

              Document each argument of taint_propagation
              Refactor arguments of taint_propagation

              Python 3
              .treerc
              .coveragerc
              setup.py
              requirements.txt
              tox.ini
              Create Python code anonymizer via AST so that users can submit their real code with just the variables etc. changed
              Make log statements that tests depend on log.error or log.exception and the rest log.debug
              We are missing tainted integers via DIVIDE not propagating taint I think, lame vuln. Do later.
              Put the interprocedural_mode in a feature flag, in a config yml file?
              Create a "Clean exceptions" function? Right now it's inlined in 2 different places
              Replace str typecasts with wrapper that logs when it isn't needed.
              After my 4 tests pass, anonymize my 2 huge successful test cases for tracking open-redirects
              Better documentation
              Remove the instrumentation leftover from equip
              Clean the code
              Why are my models written like Java Romain? :D
              Maybe bools shouldn't track taint?
                No, they should
WOULD BE NICE
        ????? If there is more than 1 name that matches throw an error?
        # TODO: Out of curiosity, when would the compiler not be able to STORE_FAST and have to STORE_NAME?
            # In other words, can't "Store TOS into the local co_varnames[var_num]"(STORE_FAST) so it has to use co_names
        See if I need to handle frames
        Combine BasicBlocks when graphing that are only separate because they're on different lines (i.e. they're still in the same BasicBlock but appear not to be)
DONE
              Part D:
                    Remove duplicates from output
              Part B:
                    There are many false positives, mostly due to any_function(infected) returning a tainted value, turn this off with a feature flag.
              Part C:
                    Get rid of "run #of_args times" to create a proper summary
                      I do not think forward slicing is necessary, just keep a tainted_by dictionary inside the interpreter
                      Upon "a = infected" just make tainted_by[a] = tainted_by[infected]
                      A small problem arises when one thing is tainted_by multiple things
                        test case:
                              "a = something(infected_a, infected_b)"
                              obviously the solution is to have both values in tainted_by[a] but the implementation requires thought

                    This may also help with "If this is a tainted arg e.g. "c.next = request.params.get('next')", say request.params.get('next') is the arg, not c.next."
                      by checking tainted_by[c.next] and getting request.params.get('next')

                    DONE Test tainted_by with 2 assigns
              DONE -- TEST BUDDY system on or
              Part A:
                    DONE There are duplicate vulns, investigate if the buddy system has a bug.
                    There are lots of unhandled graphs:
                          Handled graphs, diamond and triangle:
                              A
                             / \
                            B   C
                             \ /
                              D

                              A
                              |\
                              | B
                              |/
                              C

                          Impossible Graph, due to number of children being limited to 2:
                              A
                              |\\
                              | BC
                              |//
                              D

                          The problem graph, completed in test_dupes:
                              A
                              |\
                              | B
                              |/ \
                              D<--C

                             Code:
                              if A and B:
                                C
                              D

                             A does:
                              Do not execute D, because it's the buddy
                              Execute B
                                B Does:
                                  Do not execute D, because it's the buddy
                                  Execute C
                                  Jump to D
                              Jump to D

                              We want it to become:
                                 A does:
                                  Do not execute D, because it's the buddy
                                  Execute B
                                    B Does:
                                      Do not execute D, because it's the buddy
                                      Execute C
                                      See that D is not just the last element of stack_of_buddies, but also the 2nd to last
                                        So do not jump to D
                                        Merge C and B
                                        return
                                  Jump to D

                          Another problem graph, completed in test_dupes2:
                              A
                              | \
                              B->C
                              | /
                              D

                              Code:
                               if A or B:
                                 C
                               D

                              A really does:
                                Execute B
                                  B Does:
                                    Do not execute D, because it's the buddy
                                    Execute C
                                      Execute D
                                    Jump to D
                                Execute C
                                    Execute D


                              WHY IS C THE BUDDY OF A?
                                  because I fucked up :(

                              When C executes, what is stack_of_buddies?

                              In other words, it does:
                                    a -> c -> d
                                    b -> c -> d
                                    b -> d


                              We want it to become:
                                 A does:
                                    Execute B
                                      B Does:
                                        Do not execute D, because it's stack_of_buddies[-1]
                                        Execute C
                                          Do not execute D, because it's stack_of_buddies[-1]
                                          Return
                                        Merge B and C
                                        Return
                                    Execute C
                                        Do not execute D, because it's stack_of_buddies[-1]
                                        Return
                                    Jump to D




                          Another problem graph, completed in test_dupesN:
                              A
                              |\
                              | B
                              |/ \
                              |   C
                              | /  \
                              |/    D
                              |    / \
                              |   /   \
                              |  /     \
                              | /       \
                              |/         \
                              |           \
                              F<-----------E

                             Code:
                              if A and B and C and D:
                                E
                              F

                          Another problem graph, completed in test_dupes2N:
                                     A
                                    / \
                                   B-->\
                                  /     \
                                 C------>\
                                /         \
                               D---------->\
                              /             \
                             F<--------------E

                             Code:
                              if A or B or C or D:
                                E
                              F


                              Right now it does:
                                ????

                              We want it to become:
                                 A does:
                                    Push F
                                    Execute B
                                      B Does:
                                        Push F
                                        Do not execute F, because F == stack_of_buddies[-1]
                                        Execute C
                                          C Does:
                                            Push F
                                            Execute D
                                              D Does:
                                                Push F
                                                Execute E
                                                  E Does:
                                                    Do not execute F, because F == stack_of_buddies[-1]
                                                    Return
                                                See that stack_of_buddies[-2] == stack_of_buddies=[-1], return Me + E
                                            See that stack_of_buddies[-2] == stack_of_buddies=[-1], return Me + D
                                        See that stack_of_buddies[-2] == stack_of_buddies=[-1], return Me + C
                                    Merge Me + B
                                    Jump to F



                                 But what all the nodes executing E?



                                 A does:
                                    Push F
                                    Execute B
                                      B Does:
                                        Push F
                                        Do not execute F, because F == stack_of_buddies[-1]
                                        Execute C
                                          C Does:
                                            Push F
                                            Execute D
                                              D Does:
                                                Push F
                                                Execute E
                                                  E Does:
                                                    Do not execute F, because F == stack_of_buddies[-1]
                                                    Return
                                                See that stack_of_buddies[-2] == stack_of_buddies=[-1], return Me + E
                                            See that stack_of_buddies[-2] == stack_of_buddies=[-1], return Me + D
                                        See that stack_of_buddies[-2] == stack_of_buddies=[-1], return Me + C
                                    Merge Me + B
                                    Jump to F
        [Intraprocedural] Grab the dominators fix from https://github.com/neuroo/equip/issues/2
        Write a command-line interface, steal The Face of Bandit
        Give everything an __init__.py
        Intraprocedural
              Part 1b:
                    Fix path explosion

                      Use the buddy system
                            on join nodes (those with more than 1 child),
                            wait until all the brothers and sisters show up at that node,
                            merge taint sets,
                            proceed as one.
              Part 1a:
                      Set up the buddy system
                            start at the root with a UUID
                            at each diverge, create a UUID.
                            LIFO
                              refresh UUID at join point.
                            if current_block is a join point,
                            A problem with my buddy system:
                                  Block A
                                  ------
                                  Block B (if was True)
                                  ------
                                  Block C

                                  Block C is the join node
                                  Problem with regular BFS:
                                    B sees A1
                                    C sees A2
                                    C never sees A1

                                    C needs to be the 'current' node twice
                                    or maybe every if statement needs a fake else statement attached?
        Interprocedural Part 4: Does what I'm calling return a tainted value?
            Test -> Calling a function with a sink + Returns a tainted value

            Callee
              When you're in a BasicBlock that is marked as current_block.has_ret_value
              if what's at the top of the stack is in tainted,
              decl returns_tainted = True

              then in the param loop we toss it over to all_params_returns_tainted
            Caller
              we threw the tainted arguments and check if all_params_returns_tainted['argument'] is True

            We just ran into caller being dis'd before callee :/
            I solved it via the ugly:
                for decl in reversed(bytecode_object.declarations):
            Notes in general
                DONEIn taint_permutation wrapper:
                        - What sinks are reached if arguments A or B or C are tainted?
                                - We need to run the Declaration through taint_propagation N times, where N is the number of arguments
                                    - Right now we're only passing "tainted=set(decl.formal_parameters)" into taint_propagation
                        - What arguments are tainted in function calls?
                            - We will need to combine the output of the N runs, so that we can say "both B and C" are tainted when calling X
                DONEIn call_function:
                          For interprocedural_mode, we record: the function being called,
                                                               what arguments of the function are tainted
                                - What return values are tainted if arguments A or B or C are tainted?
                                - What about tainted return values? We'll want to handle this
                                        Option A: We have the summary of callee_decl when we call it.
                                        Is there an Option B?
                In lookup function:
                        DONE- One thing left on the stack
                        DONE- Loop through return_value seeing what parts of it are in tainted?
        Interprocedural Part 3: Call lookup function in call_function
                          The lookup function just takes in the decl :) which holds the summary
                          First off, made a vuln_summary and an all_params_vuln_summary
                          Ran into over tainting on all subsequent args, (grepping for all_params_vuln_summary in logs shows this)
                              Added
                                  # We clean the slate for the next param
                                  decl.vuln_summary = []
                          After that, we did
                                for vuln_key in callee_decl.all_params_vuln_summary.keys():
                                    if vuln_key in callee_tainted_args:
                                      woohoo
                                e.g.  all_params_vuln_summary={'heehaw': [{'sink': 'self.redirect', 'tainted_args': 'biatch'}]}
        Interprocedural Part 2: taint_permutation wrapper (in the form of a test? or another function? test for now) that records function summaries
                          Store where? The Declaration object?
                          How do we want to store the (called_function, tainted_args) in the Declaration object?
                                              Either we have to run things N times for each arg (simple)
                                              or we have to do forward slicing (sexy and faster)
                                              We can do N times for now
                          How do we want to store the (sink, tainted_args) in the Declaration object?
                          Answer is:
                                Here it is :)
                                  test_interprocedural.py::test_interprocedural2(178) -
                                  {'self': [{'method': 'inter_procedural', 'tainted_args': set(['default', 'other', 'argument'])}]}
        Interprocedural Part 1: Record what function is being called and what arguments are tainted, in call_function
        See Why is inlining painful with my approach? to know why "We call __taint_propagation on the Declaration and have it return just it's return value" won't work
        Write the (failing) test of Issue 3/3
            issue3   --
                    KeyError: kwargs, resulting from def function(..., **kwargs):
        Pass the test of Issue 3/3
        Pass the test of Issue 1/3
        Wrote the (failing) test of Issue 1/3
        Test 2nd of Open Redirects, Got 3 Issues!
        Fixed the test_tryexcept bytecode messing up the stack
        Test 3 get_money.py (purposely not in the tests, too big to anonymize the code)
        Test 4 tada
        Test 2 SLICE+2 & SLICE+1 BUILD_SLICE
        Test 1 UNPACK_SEQUENCE
        24 controllers in big_file.py, how many are done? All but 4 I think

The only tests that currently pass are:
        test_decl
        test_graph
        test_control_flow
        test_miscellaneous
        test_interprocedural

If you see
>       if val in self.tainted:
E       TypeError: unhashable type: 'klist'

Just add str() around val


Interesting grep:
  cat junkhacker.log.py | grep "NEW INVOCATION OF taint_propagation "|wc -l

Path explosion affects the real
  s**_d**
  g**_o**_d**


Why is inlining painful with my approach?
Summaries will work a million times better than inlining because of the way __taint_propagation works, I can't return all current_interpreter's() of the root and all of it's children's current_interpreters (all paths in a program) and expect that to work well.


Remind me again, bound vs unbound method in Python means what?

There's nothing with Python that is a sink when called twice, e.g. fclose etc.

return is a sink
