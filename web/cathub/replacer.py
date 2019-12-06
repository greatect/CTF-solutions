i = str(input())
o = ''
for c in i:
	if c == ' ':
		o += '%0D'
	else:
		o += c
print(o)
