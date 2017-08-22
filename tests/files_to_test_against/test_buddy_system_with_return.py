def picky(self):
    infected = request.params.get('hey')
    ray = orange.grab.this('ray', None)
    # lenny = 't' if ray is not None else 'f'
    briscoe, law = And.order(orange.environ,
        orange.grab)
    if law and not briscoe:
        return guilty(law)
    self.redirect(infected)
