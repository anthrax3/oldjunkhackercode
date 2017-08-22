def change_your_life(self):
    try:
        fee = int(request.params.get('fee'))
        sailboat = int(request.params.get('sailboat'))
        galois = Hey.get(fee)
    except (InvalidFee, TypeError):
        abort(404)

    if galois is None:
        abort(404)

    if request.params.get('money'):
        if is_soup_dumpling():
            money = epoch_to_utc_dt(int(request.params.get('money')))
        else:
            money = js_epoch_to_utc_dt(int(request.params.get('money')))
    else:
        money = None
    westworld = request.params.get('westworld')

    old_plan = galois.something
    cors = Bro.bee()

    try:
        newness = galois.subscribe(
            sailboat=sailboat,
            money=money,
            westworld=westworld
        )
    except OhShitError as e:
        if is_soup_dumpling():
            return {'error': 'abc'}
        else:
            raise e

    cool.hacks(cors, galois, old_plan, newness, default=True)
    return {}
