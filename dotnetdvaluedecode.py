#!/usr/bin/env python
#
# This is forked from https://github.com/inquisb/miscellaneous/blob/master/ms10-070_check.py to add a bit more functionality
#
# PoC for checking if MS10-070 patch is applied by providing a .NET
# application ScriptResource or WebResource resource handler's 'd' block
#
# Credits go to:
#
# * Juliano Rizzo - for the amazing research and hints about the remote
#   passive check
#   <http://twitter.com/julianor/status/26419702099>
#
# * Brian Holyfield - for his tool to exploit Padding Oracle attacks in a
#   generic and easy way
#   <https://www.gdssecurity.com/l/t/d.php?k=PadBuster>
#
# * Giorgio Fedon - for initial Perl version of this check
#   <http://blog.mindedsecurity.com/2010/09/investigating-net-padding-oracle.html>
#
# * Alejo Murillo Moya - for testing and ideas
#
#
# Copyright (c) 2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
#
#
# Example of unpatched system:
#
# * /WebResource.axd?d=kHoDoPikaYfoTe1m9Ol5iQ2
# * /ScriptResource.axd?d=2nYOzoKtRvjs-g53K3r7VKmEXeQl_XMNY8nDEwcgwGVcS5Z8b9GanbNdzIgg493kfB_oInMb2DtFFEy5e-ajqdwMbg1F96l10
#
# Examples of patched system:
#
# * /WebResource.axd?d=VHYaLecZ91Zjq-_4mV3ftpYrTteh9kHzk9zwLyjpAZAOjWL3nbx1SmIeGdHJwBu_koMj8ZGAqrtxCJkW0
# * /ScriptResource.axd?d=Gcb5Zt1XkIPHAYC3l5vZ4QidrZMKISjkqnMQRQDqRD88oxkWIL1kNBQThGrDJBbaKqPd9AyT-jF1EhM-rame5NXv7RLQRhtlz-xfoQlHXf_pjgiBJW7ntGxhegohUeNFlo9x8_RMU6ocDmwwK6dfIRDFbX01
import base64

import sys

def dotNetUrlTokenEncode(string):
    """
    Ported from padbuster v0.3 by Brian Holyfield:

    sub web64Decode {
     my ($input, $net) = @_;
     # net: 0=No Padding Number, 1=Padding (NetUrlToken)
     $input =~ s/\-/\+/g;
     $input =~ s/\_/\//g;
     if ($net == 1)
     {
      my $count = chop($input);
      $input = $input.("=" x int($count));
     }
     return decode_base64($input);
    }
    """
    return base64.urlsafe_b64encode(string)# string.urlsafe_b64encode()

    string = string.encode("base64")

    string = string.replace("+", "-").replace("/", "_")
    count = string[-1]

    #if count.isdigit():
    #    string = string[:-1] + ("=" * int(count))

    return string

#from https://github.com/inquisb/miscellaneous/blob/master/ms10-070_check.py
def dotNetUrlTokenDecode(string):
    count = string[-1] #last char

    if count.isdigit(): #strip off number of last item in string for some reason
        string = string[:-1] + ("=" * int(count))
    return base64.urlsafe_b64decode(string)

def isVulnerable(decodedstring):
    return len(dotNetUrlTokenDecode(decodedstring)) % 8 == 0

def usage():
    print """
Use:

  ./ms10-070_check.py <encrypted_d_block>

Note:

  Encrypted 'd' block MUST be from ScriptResource.axd or WebResource.axd.
  Parse the application response body to find a valid one.

Examples:

dotnetdvaluedecode.py -d VHYaLecZ91Zjq-_4mV3ftpYrTteh9kHzk9zwLyjpAZAOjWL3nbx1SmIeGdHJwBu_koMj8ZGAqrtxCJkW0
Decoded d value: <binary output>
Length: 60
D value length of 60 is not evenly divisible by 8, your application is patched

Z:\Desktop\Client\AttackTools\DotNetDValueDecode>python dotnetdvaluedecode.py -d 2nYOzoKtRvjs-g53K3r7VKmEXeQl_XMNY8nDEwcgwGVcS5Z8b9GanbNdzIgg493kfB_oI
Length: 72
D value length of 72 is evenly divisible by 8, 8our application is likely vulnerable (try more d values if unsure)

  With ScriptResource.axd 'd' block:
  $ ./dotnetdvaluedecode.py -e 2nYOzoKtRvjs-g53K3r7VKmEXeQl_XMNY8nDEwcgwGVcS5Z8b9GanbNdzIgg493kfB_oInMb2DtFFEy5e-ajqdwMbg1F96l10
  Your application is VULNERABLE, patch against MS10-070

  With WebResource.axd 'd' block:
  $ ./dotnetdvaluedecode.py -e asdfasdfasdfasdf123123123234
  YXNkZmFzZGZhc2RmYXNkZjEyMzEyMzEyMzIzNA==
  Length:
  40
"""

def main():
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    encode = sys.argv[1]
    d = sys.argv[2]

    if sys.argv[1] == '-e':
        print dotNetUrlTokenEncode(d)
        print "Length: " + str(len(dotNetUrlTokenEncode(d)))
    elif sys.argv[1] == '-d':
        print "Decoded d value: " + str(dotNetUrlTokenDecode(d))
        print "Length: " + str(len(dotNetUrlTokenDecode(d)))

        if isVulnerable(d):
            print "D value length of " + str(len(dotNetUrlTokenDecode(d))) + " is evenly divisible by 8, your application is likely vulnerable (try more d values if unsure)"
        else:
            print "D value length of " + str(len(dotNetUrlTokenDecode(d))) + " is not evenly divisible by 8, your application is patched"

if __name__ == '__main__':
    main()