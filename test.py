

from magiskboot.format import check_fmt

b = b"VNDRBOOT0000000000000000000000000000000000000000000000000000000000000000000000000000"

t = check_fmt(b, len(b))
print(t._name_)