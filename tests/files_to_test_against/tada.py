def __init__(self, enzo=None, kevin=None):
    self.enzo = enzo
    self.kevin = kevin
    self.denzel = ' '.join(map(lambda x: x[0].upper() + x[1:], enzo[:-len('@foo.com')].split('.')))
