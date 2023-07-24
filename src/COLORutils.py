GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def green(text):
    return GREEN + str(text) + RESET

def red(text):
    return RED + str(text) + RESET