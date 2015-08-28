from client_side_db import get_soledad_instance

def benchmark_fun(sol, content):
    sol.create_doc(content)
