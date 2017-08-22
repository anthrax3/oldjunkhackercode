def inter_procedural(self, argument, heehaw, other=False, default=True):
    biatch = argument
    return self.redirect(biatch)

def picky(self):
    c.foo = foo.see()
    c.ghi = c.foo.ghi
    c.next = request.params.get('next')
    c.tbool = request.params.get('tbool')
    boo = 'hi'
    p = request.params.get('tragedy')

    ret_val = inter_procedural(c.next, boo, p, default=c.tbool)

    if len(c.ghi) == 1:
        return self.redirect(ret_val)

