def issue3(cls, bing_bong=None, **kwargs):
    # This would work
    # wtf = {'hey': 'test', 'boo':'yo'}
    # bread = hey(whatup='fooz', ball='banana', **wtf)
    # This does not
    bread = hey(whatup='fooz', ball='banana', **kwargs)
    said = bing_bong or request.params.get('error', bread)
    try:
        said.encode('Chet')
        said = unicode(said)
        if cls.red(said):
            return said
        else:
            return bread
    except UnicodeEncodeError:
        return bread
