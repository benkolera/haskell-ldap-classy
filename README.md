# ldap-classy

This is an attempt to write a safer layer over the top of the
[LDAP](http://hackage.haskell.org/package/LDAP)
C bindings.

This comes in three main parts:

- Providing Types and functions for representing and combining DNs and SearchFilters.
- Providing safe way to serialize these to strings and back.
- Providing some ToLDAPEntry FromLDAPEntry typeclasses for going back and forth between Entries
  and haskell data types.

It's a possibility that the Dn and SearchFilter stuff gets separated from the Typeclass stuff as
the encode/decode to/from entry makes use of mtl and classy optics because it fits into our
application better that way. :) 

## RFCs 

There have been a number of RFCs consulted in the making of the escaping rules:

- [RFC4514](https://tools.ietf.org/html/rfc4514) - String Representation of Distinguished Names
- [RFC4512](https://tools.ietf.org/html/rfc4512) - Directory Information Models
- [RFC4515](https://tools.ietf.org/html/rfc4515) - String Representation of LDAP Search Filters
