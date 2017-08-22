from my.model import Alice

def ghi(self):
    foo = Decimal(request.params.get('foo', 0))
    sdk = request.params.get('sdk', '')
    consumer = request.params.get('consumer', '')
    fast = request.params.get('zip', None)
    if consumer and foo > 0:
        my_kwargs = {'user': Alice.me(), 'fast': fast, 'consumer': consumer}
        with my_context('/abc/ghi', **my_kwargs) as bop:
            print 'foo'
