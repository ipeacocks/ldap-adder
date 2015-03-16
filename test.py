from inspect import getsourcefile
from os.path import abspath

abs_path = abspath(getsourcefile(lambda _: None))
print abs_path