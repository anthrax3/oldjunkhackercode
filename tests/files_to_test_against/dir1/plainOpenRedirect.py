def picky(self):
    c.next = request.params.get('next')
    c.tboo = request.params.get('tboo')

    if 'hi' == c.next:
        print 'hi'
    else:
        print 'goodbye'

    self.redirect(c.next)
    # Does this have 1 thread or 2?
    return self.redirect(c.tboo)
