This code is a working proof of concept provided for research purposes only.

## Prereqs
Tested on Linux and OSX.  Requires C++ Boost and OpenSSL.

## Building
```
g++ -m64 -O3 nxtminer.cpp -lpthread -lboost_thread -lboost_system -lcrypto -o nxtminer
```

## Running
Input a file full of DarkNXT "account_id balance" pairs.  A file with all DarkNXT accounts circa 2014-07-30 is included.  This program simply prints keys as it finds them.

#### Example
```
drevil@moonbase$ ./nxtminer accounts.txt
seed: A2B3FB0679E5DD5F78474D29FC46E4CB
searching 3000 accounts
calibrating ... 8079424 keys/sec
found 10000 NXT in account 91287652353
  secret exponent = 912197312763274508004875726143510601078532313485910883819074248248413254622
found 1029 NXT in account 477285589561
  secret exponent = 5711902112917968172388391637344674610847573639645992410606244194250296554281
```

## Notes
It's worth noting that the private keys output by this program are nonstandard in several respects. NXT creates private keys by SHA256'ing a passphrase and using the little-endian output as anexponent after first tweaking a few bits in the number to ensure it's safe per the Curve25519 rules.  This program outputs untweaked exponents and so you'll need special software to create transactions with these keys.

As far as ROI on running this; frankly, it blows.  This was primarily coded up just for shits and giggles. 

Here are the numbers (as of early August 2014).

There are ~17k DarkNXT accounts with a combined value of ~20m NXT. The top 3k accounts comprise (99.8%) of the value. If we restrict our attention to just this top 3k:

* mean = 6795 NXT
* median = 479 NXT
* stddev = 56987 NXT

The skew on this distrubtion means returns will be very uneven.

I estimate a risk neutral rational miner needs to search @ ~250M keys/sec to average 1 USD per day. Core-i7 speed for this code is ~8M keys/sec.  250M keys/sec might be doable if you port this to OpenCL and run it on a high end GPU.  Add in pooling and it could start to make sense but mining more profitable cryptocurrencies would still make a lot more sense.

I should also point out that as more and more DarkNXT gets mined, ROI [decreases](https://en.wikipedia.org/wiki/Coupon_collector%27s_problem). 
