def inter_procedural(self, argument, heehaw, other=False, default=True):
    return self.redirect(heehaw)

def picky(self):
    c.foo = foo.me()
    c.ghi = c.foo.ghi
    c.next = request.params.get('next')
    c.tbool = request.params.get('tbool')
    boo = 'hi'
    peaches_was_killed_by_my_girlfriend = request.params.get('tragedy')

    ret_val = inter_procedural(c.next, boo, peaches_was_killed_by_my_girlfriend, default=c.tbool)

    if len(c.ghi) == 1:
        return self.redirect(ret_val)

