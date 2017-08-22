def picky(self):
    c.next = request.params.get('next')
    c.tboo = request.params.get('tboo')

    denzel = washington.pie(c.tboo)

    return self.redirect(denzel)
