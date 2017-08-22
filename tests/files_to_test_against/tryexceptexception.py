def tryexceptexception(self):
    dough = request.params.getall('bop[]')
    peaches = request.params.get('peaches')
    chef = request.params.get('chef')

    if dough and peaches and chef:
        try:
            for pound in dough:
                Cake.bdx("merge_orgs", pound, peaches, chef)
        except Exception:
            return {"message": "Failed"}
        return {"message": "success"}
    else:
        return {"message": "Yo"}
