#What we had:
from Crypto.Util.number import getStrongPrime, GCD
from random import randint
from flag import flag
import os

def pad(m: int, n: int):
  # PKCS#1 v1.5 maybe
  ms = m.to_bytes((m.bit_length() + 7) // 8, "big")
  ns = n.to_bytes((n.bit_length() + 7) // 8, "big")
  assert len(ms) <= len(ns) - 11

  ps = b""
  while len(ps) < len(ns) - len(ms) - 3:
    p = os.urandom(1)
    if p != b"\x00":
      ps += p
  return int.from_bytes(b"\x00\x02" + ps + b"\x00" + ms, "big")


while True:
  p = getStrongPrime(512)
  q = getStrongPrime(512)
  n = p * q
  phi = (p-1)*(q-1)
  e = 1337
  if GCD(phi, e) == 1:
    break

m = pad(int.from_bytes(flag, "big"), n)
c1 = pow(m, e, n)
c2 = pow(m // 2, e, n)

print("n =", n)
print("e =", e)
print("c1=", c1)
print("c2=", c2)

#OUTPUT:
n = 113135121314210337963205879392132245927891839184264376753001919135175107917692925687745642532400388405294058068119159052072165971868084999879938794441059047830758789602416617241611903275905693635535414333219575299357763227902178212895661490423647330568988131820052060534245914478223222846644042189866538583089
e = 1337
c1= 89077537464844217317838714274752275745737299140754457809311043026310485657525465380612019060271624958745477080123105341040804682893638929826256518881725504468857309066477953222053834586118046524148078925441309323863670353080908506037906892365564379678072687516738199061826782744188465569562164042809701387515
c2= 18316499600532548540200088385321489533551929653850367414045951501351666430044325649693237350325761799191454032916563398349042002392547617043109953849020374952672554986583214658990393359680155263435896743098100256476711085394564818470798155739552647869415576747325109152123993105242982918456613831667423815762
#So first, let's think a little bit. We see that we have 2 ciphers c1 and c2. c1 = m**e mod(n) and c2 = (m//2)**e mod(n)
#If we change a bit the second equation, we can find that c2 * 2**e = m**e mod(n) OR c2 * 2**e = (m-1)**e mod(n), depending if m is an even or an odd number

#Let's assume that m is an odd number, then let's call c3 the cipher text of m-1
#we have c2*2**e = (m-1)**e mod(n)

#let's calculate c3
c3=c2*(2**e)%N

#So we have c3 = (m-1)**e %N and c1 = m**e %N 
#If we find the greatest common divisor between m**e %N - c1 and (m-1)**e %N - c3 we will be able to write m as m = a(m-1) + b = m

#Now , we use an algorithm that I found in a writeup of an other challenge : https://github.com/death-of-rats/CTF/tree/master/Dice2021/plagiarism 
#And we change value from c1 to our c1, c2 to our c3, e to our e and N to our N.
#Then we can see the flag at the end : b'\x02\x81\xae\xed \xdd\x07\x12;\x99\xc7d:\x99\x1a8\x16\xfe\xe6<\x18\x1dw\xea&\xfb\xfc\x8a\xa7\xa8\xba\xfa\xd8\xbe\xdf\x01\x13\xcb\xd3\x99\x9c\xf3_\x18qw\xb99}\'Q\xd7~\x03&^\xcd\x9aw\xf0\xef\xb5\x04\x1b\xb7\n\xe1\xcd"\x95ff]\x0c(H\x99\xb5\xed\xc3\x82\x9dl\xe4\x8c\xddx\xfd\x00zer0pts{y0u_g07_47_13457_0v3r_1_p0in7}'









