def picky(self):
    c.next = request.params.get('next')
    c.tboo = request.params.get('tboo')
    test = 'foo'
    if 'hi' == c.next:
        print 'hi'
    else:
        test = request.params.get('now_you_infected')
        print 'goodbye'

    # Does this have 1 thread or 2?
    return self.redirect(c.tboo)
