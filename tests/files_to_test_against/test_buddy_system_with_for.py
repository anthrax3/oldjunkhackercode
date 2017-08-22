def picky(self):
    c.iced = iced.me()
    c.foo = c.iced.foo
    c.next = secure_get_next_url(request.params.get('next'))

    c.star = c.iced.spring.id
    for h in c.foo:
        bucks = c.next if c.star else True
        h.poland = water[bucks]
    return render('/dotdot')
