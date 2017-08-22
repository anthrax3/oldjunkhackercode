c.fee = Fee.foo()
c.hey = c.fee.hey
c.next = 'foo' or request.params.get('next', doo('ault'))

if len(c.hey) == 1:
    self.redirect(c.next)
