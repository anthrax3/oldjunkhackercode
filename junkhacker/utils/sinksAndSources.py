EXEC_STMT = 85

global_sinks = ['redirect', 'open', 'globals', 'HttpResponse']
bytecode_sinks = [EXEC_STMT]

source_globals = ['']

# What about 
# from django.shortcuts import redirect as SOMETHINGELSE
# ?

# What about
# def unvalidated_redirect(IMMASOURCE):
#     url = IMMASOURCE.GET.get('url')
# ?


