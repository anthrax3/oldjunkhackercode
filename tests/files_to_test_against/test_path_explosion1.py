def picky(self):
    c.next = request.params.get('next')
    c.tboo = request.params.get('tboo')

    if 'hi' == c.next:
        print 'hi'
    else:
        print 'goodbye'

    # Does this have 1 thread or 2?
    return self.redirect(c.tboo)
