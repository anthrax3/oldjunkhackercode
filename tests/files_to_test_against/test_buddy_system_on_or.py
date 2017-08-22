def picky(self):
    c.next = request.params.get('next')
    c.tboo = request.params.get('tboo')

    abby = abby.pie()
    if abby or not something(1):
        self.redirect(c.next)
    # Does this have 1 thread or 2?
    return self.redirect(c.tboo)
