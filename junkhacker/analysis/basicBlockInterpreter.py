"""
  junkhacker.analysis.basicBlockInterpreter
  ~~~~~~~~~~~~~~~~~~~

  Creates summaries of taint tracked bytecode basic blocks.
"""
import dis
import json
import operator
import traceback

from ..utils.log import logger

# TODO: Fix this, put it in ONE file
GLOBAL_SINKS = ['globals', 'HttpResponse','open','redirect','self.redirect','time.sleep', 'request.params.get']
SANITIZERS = ['nothing yet']
default_immune = {
    'execute_sql':['escape_sql'],
    'globals':['nothing'],
    'HttpResponse':['nothing'],
    'open':['nothing'],
    'redirect':['nothing'],
    'self.redirect':['nothing'],
    'time.sleep':['nothing']
}
# TODO: Fix this, put it in ONE file

class kdict(dict):
   def __init__(self,*arg,**kw):
      super(kdict, self).__init__(*arg, **kw)

class klist(list):
    """
        Represents the type list in basicBlockInterpreter
    """
    def __init__(self,*arg,**kw):
      super(klist, self).__init__(*arg, **kw)

class slicey(object):
    """
        solely used for
        slice_operator
        and
        binary_operator
        etc.
    """
    def __init__(self, l, tainted, start, end, step=None):
        self.start = start
        self.end = end
        self.step = step
        self.original_list = str(l)
        self.tainted = tainted

    def __str__(self):
        if self.step:
            return self.original_list +"["+str(self.start)+":"+str(self.end)+":"+str(self.step)+"]"
        return self.original_list +"["+str(self.start)+":"+str(self.end)+"]"

class seq_index(object):
    """
        solely used for
        UNPACK_SEQUENCE
        STORE_FAST
    """
    def __init__(self, seq, index, tainted):
        self.seq = seq
        self.index = index
        self.tainted = tainted

    def __str__(self):
        return str(self.seq)+" index "+str(self.index)

class BasicBlockInterpreterError(Exception):
    """For raising errors in the operation of the BasicBlockInterpreter."""
    pass

class BasicBlockInterpreter(object):
    """
        Interprets a single line of Python, code mostly copied from Byterun.
    """
    def __init__(self, stack, current_decl, tainted=set(), environment={}, immune={}, other_decls=None, interprocedural_mode=False, score=[], tainted_by={}):
        self.stack = stack
        self.tainted = tainted
        self.tainted_by = tainted_by
        logger.debug("tainted is %s", tainted)
        logger.debug("type(tainted is %s", type(tainted))
        logger.debug("tainted_by is %s", tainted_by)
        logger.debug("type(tainted_by is %s", type(tainted_by))

        # Anything from a request is tainted
        self.tainted.add("request")

        self.environment = environment
        self.score = score
        self.immune = default_immune.copy()
        self.immune.update(immune)

        # self._interprocedural_mode = interprocedural_mode
        self._interprocedural_mode = False

        self.called_functions = []

        self.current_decl = current_decl
        self.other_decls = other_decls

    def __repr__(self):
        # could add the other_decls attribute
        return 'BasicBlockInterpreter(\n\tstack=%s\n\tcalled_functions=%s\n\tenvironment=%s\n\ttainted=%s\n\timmune=%s)' \
               % (self.stack, self.called_functions, self.environment, self.tainted, self.immune)

    def _add_to_tainted(self, arg, name):
        if isinstance(arg, basestring):
            if 'return value of' in arg:
                logger.debug("what the fuck, arg is %s and name is %s", arg, name)
        if name not in self.tainted:
            self.tainted.add(name)

        # arg = str(arg)
        if not isinstance(arg, basestring):
            logger.error("[pajamas]The type of arg is %s", type(arg))
            if isinstance(arg, seq_index):
                arg = str(arg)
            else:
                raise
        if not isinstance(name, basestring):
            logger.error("[pajamas]The type of arg is %s", type(arg))
            raise
        # name = str(name)
        # begin the tainted_by code

        # I am sorry, I know I can do better
        # Remove dupes
        if name in self.tainted_by.keys():
            for val in self.tainted_by[name]:
                if val == arg:
                    return
                if arg in self.tainted_by.keys():
                    if val == self.tainted_by[arg]:
                        return
                    for hmm in self.tainted_by[arg]:
                        if val == hmm:
                            return

        # Propagate tainted_by
        if arg in self.tainted_by.keys():
            if name in self.tainted_by.keys():
                if isinstance(self.tainted_by[name], basestring):
                    raise
                self.tainted_by[name].extend([self.tainted_by[arg]])
            else:
                self.tainted_by[name] = self.tainted_by[arg]
        else:
            if name in self.tainted_by.keys():
                if isinstance(self.tainted_by[name], basestring):
                    raise
                logger.debug("name is %s and arg is %s", name, arg)
                logger.debug("type(name) is %s and type(arg) is %s", type(name), type(arg))
                self.tainted_by[name].extend([arg])
            else:
                self.tainted_by[name] = [arg]

    def _remove_from_tainted(self, name):
        if name in self.tainted:
            self.tainted.remove(name)
            if name in self.tainted_by:
                # del self.tainted_by[str(name)]
                del self.tainted_by[name]

    ## stack helper functions

    def top(self):
        """Return the value at the top of the stack, with no changes."""
        if len(self.stack) > 0:
            return self.stack[-1]
        return None

    def pop(self, i=0):
        """
            Pop a value from the stack.
            Default to the top of the stack, but `i` can be a count from the top instead.
        """
        try:
            return self.stack.pop(-1-i)
        except IndexError:
            logger.debug(traceback.format_exc())
            raise 'foo'
        # try:
        #     return self.stack.pop(-1-i)
        # except IndexError:
        #     logger.debug("MOTHER FUCKER")
        #     logger.debug("TRYING TO POP FROM EMPTY STACK")

    def push(self, *vals):
        """Push values onto the value stack."""
        self.stack.extend(vals)

    def popn(self, n):
        """
            Pop a number of values from the value stack.
            A list of `n` values is returned, the deepest value first.
        """
        if n:
            ret = self.stack[-n:]
            self.stack[-n:] = []
            return ret
        else:
            return []

    def peek(self, n):
        """Get a value `n` entries down in the stack, without changing the stack."""
        return self.stack[-n]

    ## stack manipulation
    def byte_LOAD_CONST(self, const):
        # We need to distinguish between variable names and constant strings. Variable names can't start with *
        self.push('*const_'+str(const))

    def byte_POP_TOP(self):
        try:
            self.stack.pop()
        except IndexError:
            logger.error('wtfwTracebacktfwtfwtfwtfwtf')

    def byte_DUP_TOP(self):
        self.push(self.top())

    def byte_DUP_TOPX(self, count):
        items = self.popn(count)
        for i in [1, 2]:
            self.push(*items)

    def byte_ROT_TWO(self):
        a, b = self.popn(2)
        self.push(b, a)

    def byte_ROT_THREE(self):
        a, b, c = self.popn(3)
        self.push(c, a, b)

    def byte_ROT_FOUR(self):
        a, b, c, d = self.popn(4)
        self.push(d, a, b, c)

    ## stores
    def byte_STORE_FAST(self, name):
        arg = self.pop()
        if type(arg) is not str:
            logger.debug('%s is being stored into %s',arg, name)
        if type(arg) is seq_index:
            if arg.tainted:
                self._add_to_tainted(arg, name)
            self.environment[name] = str(arg)
            return
        elif str(arg) in self.tainted:
            self._add_to_tainted(str(arg), name)
        else:
            self._remove_from_tainted(name)
        self.environment[name] = arg

    def byte_STORE_NAME(self, name):
        arg = self.pop()
        if str(arg) in self.tainted:
            self._add_to_tainted(str(arg), name)
        else:
            logger.debug('removing %s from tainted because %s isnt tainted', name, arg)
            self._remove_from_tainted(name)
        self.environment[name] = arg

    def byte_IMPORT_NAME(self, name):
        level, fromlist = self.popn(2)
        # frame = self.frame
        # self.push(
        #     __import__(name, frame.f_globals, frame.f_locals, fromlist, level)
        # )
        self.push("__import__("+str(name)+", "+str(fromlist)+", "+str(level)+")")

    def byte_IMPORT_FROM(self, name):
        mod = self.top()
        self.push("getattr("+str(mod)+", "+str(name)+")")

    def byte_END_FINALLY(self):
        top = self.top()
        if isinstance(top, basestring):
            while top.startswith('setup-except '):
                # Order is important here
                excepty = self.pop()
                top = self.top()
                logger.debug('Popping an exception in END_FINALLY')
                if not isinstance(top, basestring):
                    break

    def byte_MAKE_FUNCTION(self, argc):
        """
        Worry about after intra-procedural stuff
        """
        name = None
        code = self.pop()
        defaults = self.popn(argc)
        self.push("Function, code="+str(code)+" and defaults="+str(defaults))

    def byte_JUMP_ABSOLUTE(self, jump):
        pass

    def byte_STORE_SUBSCR(self):
        val, obj, subscr = self.popn(3)
        obj_and_subscr = str(obj)+"["+str(subscr)+"]"
        if str(val) in self.tainted:
            self._add_to_tainted(str(val), obj_and_subscr)
        else:
            self._remove_from_tainted(obj_and_subscr)
        logger.debug('Gonna store %s inside of environment variable %s', val, obj_and_subscr)
        self.environment[obj_and_subscr] = val

    def byte_STORE_MAP(self):
        logger.error("important the stack is %s", self.stack)

        the_map, val, key = self.popn(3)

        logger.debug('the_map is %s', the_map)
        logger.debug('type(the_map) is %s', type(the_map))
        logger.debug('key is %s', key)
        logger.debug('type(key) is %s', type(key))
        logger.debug('val is %s', val)
        logger.debug('type(val) is %s', type(val))
        logger.debug("The the_map is %s, val is %s, key is %s", the_map, val, key)

        if type(the_map) is kdict:
            logger.debug("Woohoo!")
        elif type(the_map) is klist:
            logger.debug("Double Woohoo!")
        else:
            logger.exception("shit")
            raise Foo

        the_map[key] = val

        # if val in self.tainted:
        #     self.tainted.add(map_and_key)
        # else:
        #     if map_and_key in self.tainted:
        #         self.tainted.remove(map_and_key)

        self.push(the_map)

    def byte_BUILD_MAP(self, size):
        # size is ignored, though it indicates how many keys in the dictionary
        # self.push("{}")
        empty_kdict = kdict()
        self.push(empty_kdict)

    ## loads
    def byte_LOAD_NAME(self, name):
        self.push(name)

    def byte_LOAD_FAST(self, name):
        """
        This only loads variable names, which cannot be a dictionary, right?
        """
        logger.debug('name is %s', name)
        # try:
        #     name = json.loads(name)
        # except ValueError:
        #     pass
        self.push(name)

    def byte_LOAD_GLOBAL(self, name):
        self.push(name)

    ## operators
    def unary_operator(self, op):
        x = self.pop()
        operation = str(op)+"("+str(x)+")"
        self.push(operation)

    def binary_operator(self, opname):
        x, y = self.popn(2)
        logger.debug('x -->%s and y -->%s',x,y)
        logger.debug('type(x) -->%s and type(y) -->%s',type(x),type(y))
        logger.debug('opname is')
        logger.debug(opname)
        if opname is 'SUBSCR':
            logger.debug('Pushing a SUBSCR')
            self.push(x+'['+y+']')
        elif isinstance(x, slicey) or isinstance(y, slicey):
            logger.debug("consider propogating taint here if op==ADD")
            operation = opname+"("+x+", "+str(y)+")"
            self.push(operation)
        else:
            operation = opname+"("+x+", "+y+")"
            self.push(operation)

    def inplace_operator(self, op):
        x, y = self.popn(2)
        if op == 'POWER':
            self.push(x+' **= '+y)
        elif op == 'MULTIPLY':
            self.push(x+' *= '+y)
        elif op in ['DIVIDE', 'FLOOR_DIVIDE']:
            self.push(x+' //= '+y)
        elif op == 'TRUE_DIVIDE':
            self.push(x+' /= '+y)
        elif op == 'MODULO':
            self.push(x+' %= '+y)
        elif op == 'ADD':
            self.push(x+' += '+y)
        elif op == 'SUBTRACT':
            self.push(x+' -= '+y)
        elif op == 'LSHIFT':
            self.push(x+' <<= '+y)
        elif op == 'RSHIFT':
            self.push(x+' >>= '+y)
        elif op == 'AND':
            self.push(x+' &= '+y)
        elif op == 'XOR':
            self.push(x+' ^= '+y)
        elif op == 'OR':
            self.push(x+' |= '+y)
        else:           # pragma: no cover
            raise BasicBlockInterpreterError("Unknown in-place operator: %r" % op)

    def slice_operator(self, op):
        # default values
        start = 0
        end = None

        op, count = op[:-2], int(op[-1])
        if count == 1:
            start = self.pop()
        elif count == 2:
            end = self.pop()
        elif count == 3:
            end = self.pop()
            start = self.pop()
        # l is a list
        l = self.pop()
        if end is None:
            end = len(l)

        if op.startswith('STORE_'):
            raise 'Go handle it'
            # l[start:end] = self.pop()
        elif op.startswith('DELETE_'):
            raise 'Go handle it'
            # del l[start:end]
        else:
            tainted = False
            logger.debug("type l is %s", str(type(l)))
            if type(l) is str:
                if l in self.tainted:
                    tainted = True
            elif type(l) is klist:
                raise 'Check tainted attribute'
                tainted = l.tainted
            else:
                raise 'Unhandled type slicey'

            s = slicey(l, tainted, start, end)
            logger.debug("slicey is %s", str(s))
            self.push(s)

    def byte_COMPARE_OP(self, opname):
        x, y = self.popn(2)
        logger.debug("opname is %s and args are %s and %s", opname, x, y)
        self.push('False')

    ## attributes
    def byte_LOAD_ATTR(self, attr):
        obj = self.pop()
        ob_dot_attr = str(obj)+"."+str(attr)
        if str(obj) in self.tainted:
            self._add_to_tainted(str(obj), ob_dot_attr)
        self.push(ob_dot_attr)

    def byte_STORE_ATTR(self, name):
        val, obj = self.popn(2)
        attr = obj+"."+name
        if str(val) in self.tainted:
            self._add_to_tainted(str(val), attr)
        else:
            self._remove_from_tainted(attr)
        self.environment[attr] = val

        # prints
    def byte_PRINT_ITEM(self):
        item = self.pop()
        logger.debug('do nothing in PRINT_ITEM')

    def byte_PRINT_ITEM_TO(self):
        to = self.pop()
        item = self.pop()

    def byte_PRINT_NEWLINE_TO(self):
        to = self.pop()

    def byte_PRINT_NEWLINE(self):
        pass

    def byte_LOAD_LOCALS(self):
        self.push("?locals?")

    def byte_SETUP_LOOP(self, dest):
        """
        I should push
            self.push_block('loop', dest)
        """
        pass

    def byte_STORE_GLOBAL(self):
        logger.debug("Well shit ERROR EMERGENCY")

    def byte_UNPACK_SEQUENCE(self, count):
        seq = self.pop()
        tainted = False
        # We can be index specific later
        if seq in self.tainted:
            tainted = True
        for index in range(count-1, -1, -1):
            self.push(seq_index(seq, index, tainted))

    def byte_GET_ITER(self):
        self.push(str("iter("+str(self.pop())+")"))


    def byte_BUILD_TUPLE(self, count):
        elts = self.popn(count)
        self.push(str("tuple("+str(elts)+")"))

    def byte_BUILD_LIST(self, count):
        elts = self.popn(count)
        logger.debug("after elts is %s", str(elts))
        self.push(klist(elts))

    def byte_LIST_APPEND(self, count):
        """
        val = self.pop()
        the_list = self.peek(count)
        the_list.append(val)
        """
        val = self.pop()

        logger.error("important the stack is %s", self.stack)

        the_list = self.peek(count-1)
        if type(the_list) is klist:
            logger.debug("Woohoo!")
        else:
            logger.debug("shit")

        logger.debug("the_list was %s", the_list)
        the_list.append(val)
        logger.debug("after the append the_list is %s", the_list)

    def byte_FOR_ITER(self, jump):
        """
        iterobj = self.top()
        try:
            v = next(iterobj)
            self.push(v)
        except StopIteration:
            self.pop()
            self.jump(jump)
        """

        # iterobj = self.top()
        # self.push('next('+str(iterobj)+')')

        logger.debug("byte_FOR_ITER is fucked up, we can't really do anything statically")

    def byte_BUILD_CLASS(self):
        logger.debug("byte_BUILD_CLASS might be fucked up")
        name, bases, methods = self.popn(3)
        self.push(str("type(")+str(name)+", "+str(bases)+", "+str(methods)+")")

    def byte_BUILD_SLICE(self, count):
        """
            This might only be used before
                BINARY_SUBSCR
            ???
        """
        if count == 2:
            start, end = self.popn(2)
            raise 'Go handle it'
            self.push(str(start)+":"+str(end))
        elif count == 3:
            start, end, step = self.popn(3)
            self.push(str(start)+":"+str(end)+":"+str(step))
            # raise 'Go handle it'
        else:           # pragma: no cover
            raise BasicBlockInterpreterError("Strange BUILD_SLICE count: %r" % count)

    ## jumps
    def byte_JUMP_FORWARD(self, jump):
        pass

    def byte_JUMP_ABSOLUTE(self, jump):
        pass

    def byte_POP_JUMP_IF_TRUE(self, jump):
        # Pop either way e.g. !=
        self.pop()

    def byte_POP_JUMP_IF_FALSE(self, jump):
        # Pop either way e.g. ==
        self.pop()

    def byte_JUMP_IF_TRUE_OR_POP(self, jump):
        # e.g. or
        # We pop if the edge is False in __taint_propagation
        pass

    def byte_JUMP_IF_FALSE_OR_POP(self, jump):
        # e.g. and
        # We pop if the edge is True in __taint_propagation
        pass

    ## call_function*
    def byte_CALL_FUNCTION(self, arg):
        return self.call_function(arg, [], {})

    def byte_CALL_FUNCTION_VAR(self, arg):
        args = self.pop()
        return self.call_function(arg, args, {})

    def byte_CALL_FUNCTION_KW(self, arg):
        """
        kwargs stands for KeyWord ARGumentS, i.e. arguments that have set keys
        environment={'wtf': {'*const_boo': '*const_yo', '*const_hey': '*const_test'}}
        call(**wtf)
        """
        kwargs = self.pop()

        try:
            logger.debug("kwargs is --%s--", kwargs)
            logger.debug("kwargs value is --%s--", self.environment[kwargs])
            logger.debug("type(kwargs) value is --%s--", type(self.environment[kwargs]))
            if type(self.environment[kwargs]) is kdict:
                logger.debug("Woohoo!")
            else:
                logger.exception("shit")
                raise Foo
        except KeyError:
            logger.debug("kwargs is probably symbolic so we're gonna ignore it")
            return self.call_function(arg, [], {})


        return self.call_function(arg, [], self.environment[kwargs])

    def byte_CALL_FUNCTION_VAR_KW(self, arg):
        args, kwargs = self.popn(2)
        return self.call_function(arg, args, kwargs)

    # @staticmethod
    def check_tainted_arg_with_func(self, func, arg, return_value):
        if func in GLOBAL_SINKS:
            # try:
            logger.debug("Heehaw, %s is in GLOBAL_SINKS", func)
            if arg not in self.immune[func]:
                logger.debug("Uh oh spaghettios")
                logger.error('The sink %s has theainted argument %s', func, arg)
                # raise

                # Store the finding in score
                self.score.append({'sink':func, 'arg':arg, 'tainted_by':self.tainted_by[arg], 'lineno':self.lineno})
                self.current_decl.vuln_summary.append({'sink':func, 'tainted_args':arg})


            # except TypeError:
            #     logger.debug('motherfucker')
            #     traceback.format_exc()
        elif func in SANITIZERS:
            # TODO: Add return value to self.immune[sink]
            # (This is needed because different sinks have different SANITIZERS)
            pass
        else:
            # Maybe we will want to make it customizable, but that is manual effort on the part of the user, so fuck that for now
            if self._interprocedural_mode:
                logger.debug('got to else if return_value not in self.tainted:')
                # self._add_to_tainted(i_do_not_know_yet, return_value)
                raise
            else:
                logger.debug('return_value is in self.tainted')
                logger.debug('return_value is '+str(return_value))

    def call_function(self, arg, args, kwargs):
        """
        TODO
            Perform taint check for arg in NAMEDARGS, like we do with interprocedural mode
        """
        lenKw, lenPos = divmod(arg, 256)
        logger.debug("the lenKw is %s, and lenPost is %s", lenKw, lenPos)
        logger.debug("the stack is %s", self.stack)
        namedargs = {}
        logger.debug("type(kwargs) is %s and kwargs is %s", type(kwargs), kwargs)

        for i in range(lenKw):
            key, val = self.popn(2)
            logger.debug("FUCK key is %s and val is %s", key, val)
            namedargs[key] = val

        namedargs.update(kwargs)
        logger.debug('namedargs is %s', namedargs)
        posargs = self.popn(lenPos)
        logger.debug("2 the stack is %s", self.stack)
        logger.debug("3 the posargs is %s", posargs)
        posargs.extend(args)
        func = self.pop()
        logger.debug('CALLED_FUNCTION --> %s   POSARGS --> %s    NAMEDARGS --> %s', func, posargs, namedargs)
        return_value = "return value of \""+str((func, posargs, namedargs))+"\""

        # Interprocedural- taint tracking, beta
        # For interprocedural_mode, we record: the function being called, what arguments of the function are tainted
        if self._interprocedural_mode:
            # For all other declarations?
            logger.error("self._interprocedural_mode is %s", self._interprocedural_mode)
            for callee_decl in self.other_decls:
                logger.debug('callee_decl is %s', callee_decl)
                logger.debug('1 type(callee_decl) is %s',str(type(callee_decl)))

                # Use isinstance below!
                raise
                if str(type(callee_decl)) == "<class 'junkhacker.bytecode.decl.ModuleDeclaration'>":
                    logger.debug('2 type(callee_decl) is "ModuleDeclaration"')
                else:
                    # Does the declaration match what's being called in my function?
                    if callee_decl.method_name == func:
                        # Ding ding ding, we have a winner

                        # Interprocedural Part 1
                        logger.debug('The function %s is called elsewhere in the code!', callee_decl.method_name)
                        logger.debug('callee_decl.formal_parameters are %s', callee_decl.formal_parameters)

                        cflow_of_callee = self.other_decls[callee_decl]

                        # copy our environment, then store in a new environment.
                        callee_env = self.environment.copy()
                        callee_tainted_args = set()

                        callee_args = list(callee_decl.formal_parameters)
                        # Hack to ignore self
                        if callee_args[0] == 'self':
                            callee_args = callee_args[1:]
                        logger.debug('callee_args is %s', callee_args)
                        logger.debug("the old environment was %s", self.environment)

                        # Loop through callee_args
                        # posargs == caller's positional arguments
                        # namedargs == caller's named arguments
                        # callee_decl.formal_parameters == callee arguments
                        for i, _ in enumerate(callee_args):
                            if i < len(posargs):
                                logger.debug("%shey %s matches %s", i, callee_args[i], posargs[i])
                                if posargs[i] in self.tainted:
                                    callee_tainted_args.add(callee_args[i])
                            else:
                                logger.debug("callee_args is %s and namedargs is %s, i is %s, type(i) is %s", callee_args, namedargs, i, type(i))
                                logger.debug("%shey %s matches %s", i, callee_args[i], namedargs["*const_"+callee_args[i]])
                                if namedargs["*const_"+callee_args[i]] in self.tainted:
                                    callee_tainted_args.add(callee_args[i])

                        logger.error("The function %s is being called with the following tainted args: %s", callee_decl.method_name, callee_tainted_args)
                        # We have now successfully recorded what function is being called and what arguments are tainted
                        self.current_decl.pretty_summary.append("The function %s is being called with the following tainted args: %s" % (callee_decl.method_name, callee_tainted_args))
                        self.current_decl.one_param_summary.append({'method':callee_decl.method_name,'tainted_args':callee_tainted_args})
                        # self.current_decl.pretty_summary.append("The function {} is being called with the following tainted args: {}".format('hey', 'biatch'))


                        # Interprocedural Part 3
                        # Look up what function(arg0, arg1, arg2) with tainted arg1 does
                        # Retrieve the return value and whether or not it's tainted
                        # logger.debug("callee_results are %s", callee_results)
                        logger.debug("part3")
                        logger.debug("These are tainted %s", callee_tainted_args)
                        logger.debug("These are tainted type(%s)", type(callee_tainted_args))
                        logger.debug("AFTER")
                        logger.debug("in call_funct callee_decl.all_params_returns_tainted is %s", callee_decl.all_params_returns_tainted)
                        # What args to the callee lead to a tainted return value?
                        for key in callee_decl.all_params_returns_tainted.keys():
                            logger.debug("all_params_returns_tainted key is %s", key)
                            # Are any of those args tainted from this caller?
                            if key in callee_tainted_args:
                                logger.error("So with argument %s there is a tainted return value! HEHEHEHEHE", key)
                                self.tainted.add(return_value)
                                # Part 4 done?
                                # Anything else?
                                #          Handle dictionaries

                        logger.debug("Are any of the above in the following dict? %s", callee_decl.all_params_vuln_summary.keys())
                        logger.debug("type o keys is  %s", type(callee_decl.all_params_vuln_summary.keys()))

                        for vuln_key in callee_decl.all_params_vuln_summary.keys():
                            if vuln_key in callee_tainted_args:
                                logger.error("Mother fucker, we just did interprocedural taint-tracking. %s is in %s", vuln_key, callee_tainted_args)
                                self.current_decl.inter_vuln_summary.append({'vuln_key':vuln_key, 'method':callee_decl.method_name})
                                logger.debug("hmm I just made this %s", self.current_decl.inter_vuln_summary)

                        logger.debug("part3 done")
        # Perform taint check
        for arg in posargs:
            logger.debug('arg is %s',arg)
            logger.debug('type(arg) is %s'+str(type(arg)))
            # try:
            if type(arg) is dict:
                logger.debug('dict as string is %s', arg)
                for key in arg.keys():
                    logger.debug('arg[\'%s\'] is \"%s\"', key, arg[key])
                    if arg[key] in self.tainted:
                        logger.debug('calling check_tainted_arg_with_func with "check_tainted_arg_with_func(%s, %s, %s)"', func, arg[key], return_value)
                        self.check_tainted_arg_with_func(func, arg[key], return_value)
            elif str(arg) in self.tainted:
                self.check_tainted_arg_with_func(func, arg, return_value)
            # except TypeError:
            #     logger.debug(traceback.format_exc())
            #     logger.debug('well shit')
            if return_value not in self.tainted:
                logger.debug('return_value aint in self.tainted')
                # if func in self.tainted:
                if func in GLOBAL_SINKS:
                    logger.debug('[selfie bullshit] tainted func is %s', func)
                    logger.debug('we are calling something self.tainted!')
                    if return_value not in self.tainted:
                        self._add_to_tainted(func, return_value)
            else:
                logger.debug('return_value is in self.tainted')
        self.called_functions.append((func, posargs, namedargs))
        self.push(return_value)

    ## and the rest of the instructions...

    def byte_POP_BLOCK(self):
        top = self.top()
        # Is just typecasting via str() better?
        if isinstance(top, basestring):
            while top.startswith('setup-except '):
                # Order is important here
                excepty = self.pop()
                top = self.top()
                logger.debug('Popping an exception in POP_BLOCK')
                if not isinstance(top, basestring):
                    break

    def byte_SETUP_EXCEPT(self, dest):
        self.push('setup-except '+ str(dest))
        self.push('setup-except '+ str(dest))
        self.push('setup-except '+ str(dest))

    def byte_SETUP_WITH(self, dest):
        """
        Real VM

        ctxmgr = self.pop()
        self.push(ctxmgr.__exit__)
        ctxmgr_obj = ctxmgr.__enter__()
        if PY2:
            self.push_block('with', dest)
        elif PY3:
            self.push_block('finally', dest)
        self.push(ctxmgr_obj)
        """
        ctxmgr = self.pop()
        self.push(ctxmgr+".__exit__")
        self.push(ctxmgr+".__enter__()")

    def byte_WITH_CLEANUP(self):
        # The code here does some weird stack manipulation: the exit function
        # is buried in the stack, and where depends on what's on top of it.
        # Pull out the exit function, and leave the rest in place.
        v = w = None
        u = self.top()
        logger.error('u is %s', u)
        if u == "*const_None":
            exit_func = self.pop(1)
        else:
            exit_func = self.pop(1)
            logger.error('exit_func is %s', exit_func)

    def byte_RAISE_VARARGS(self, argc):
        # NOTE: the dis docs are completely wrong about the order of the
        # operands on the stack!

        # exctype = val = tb = None
        # if argc == 0:
        #     exctype, val, tb = self.last_exception
        # elif argc == 1:
        #     exctype = self.pop()
        # elif argc == 2:
        #     val = self.pop()
        #     exctype = self.pop()
        # elif argc == 3:
        #     tb = self.pop()
        #     val = self.pop()
        #     exctype = self.pop()

        # TODO, handle better if needed
        logger.debug('byte_RAISE_VARARGS was ignored, fixme if needed')

    def byte_EXEC_STMT(self):
        """
            Implements exec TOS2,TOS1,TOS.
            The compiler fills missing parameters with None.
            Always returns None.
            exec(object[, globals[, locals]])
        """
        stmt, globs, locs = self.popn(3)
        if stmt in self.tainted:
            logger.debug('Uh oh spaghettios!')
            logger.debug('stmt that gets exec\'d and is tainted: %s', stmt)
        self.push('the '+stmt+' stmt got exec()\'d')

    def byte_RETURN_VALUE(self):
        logger.debug("returning %s", self.stack)

    ## currently unsupported

    # def byte_BUILD_SET(self, count):
    #     # TODO: Not documented in Py2 docs.
    #     elts = self.popn(count)
    #     self.push(set(elts))

    # def byte_SET_ADD(self, count):
    #     val = self.pop()
    #     the_set = self.peek(count)
    #     the_set.add(val)

    # def byte_MAP_ADD(self, count):
    #     val, key = self.popn(2)
    #     the_map = self.peek(count)
    #     the_map[key] = val

    # def byte_DELETE_ATTR(self, name):
    #     obj = self.pop()
    #     attr = obj+"."+name
    #     self.environment.remove(attr)

    # def byte_DELETE_SUBSCR(self):
    #     obj, subscr = self.popn(2)
    #     obj_and_subscr = str(obj)+"["+str(subscr)+"]"
    #     del self.environment[obj_and_subscr]

    # def byte_LOAD_DEREF(self, name):
    #     self.push(name+"-deref")
    #     # self.push(self.derefs[name].get())

    def dispatch(self, byteName, arguments, lineno):
        """
            Dispatch by bytename to the corresponding methods.
            Exceptions are caught and set on the virtual machine.
        """
        self.lineno = lineno
        why = None

        if byteName.startswith('BINARY_'):
            self.binary_operator(byteName[7:])
        elif byteName.startswith('UNARY_'):
            self.unary_operator(byteName[6:])
        elif byteName.startswith('INPLACE_'):
            self.inplace_operator(byteName[8:])
        elif 'SLICE+' in byteName:
            self.slice_operator(byteName)
        else:
            bytecode_fn = getattr(self, 'byte_%s' % byteName, None)
            # logger.debug('byteName is')
            # logger.debug(byteName)
            if not bytecode_fn:            # pragma: no cover
                raise BasicBlockInterpreterError(
                    "unknown bytecode type: %s" % byteName
                )
            logger.debug('byteName is')
            logger.debug(byteName)
            # LOAD_CONST can take None as an argument
            # For others 'arguments is None' means there are no arguments
            if arguments is None and byteName is not 'LOAD_CONST':
                why = bytecode_fn()
            else:
                try:
                    logger.debug('arguments are')
                    logger.debug(arguments)
                    logger.debug('type(arguments) is')
                    logger.debug(type(arguments))
                    why = bytecode_fn(arguments)
                except TypeError:
                    logger.debug(traceback.format_exc())
                    raise TypeError
                    # why = bytecode_fn()
        return why
