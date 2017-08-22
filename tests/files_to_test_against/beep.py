def beep(self):
    list_of_urls = [
        '%foo.com',
        '%haha.com'
    ]

    xyz = """
        select
            stuff
    """

    for the, donald in enumerate(list_of_urls):
        if the != 0:
            xyz += "and "
        xyz += "kevin not like '%s'\n" % donald

    xyz += """
        order by
            donald.donald asc
    """

    volatility = Foo.boo(xyz)

    blake = {}
    wtf = {}
    for key_ro, ework, can, donald in volatility:
        if key_ro not in wtf:
            wtf[key_ro] = [key_ro, ework, [can,], donald]

            # Add the donald to the dict if not present
            if donald not in blake:
                blake[donald] = 0

            blake[donald] += 1
        else:
            wtf[key_ro][2].append(can)

    e.blake = sorted(blake.iteritems(), key=lambda v: v[1], reverse=True)
    e.wtf = json.dumps(wtf.values(), indent=2)

    return billy('bush')
