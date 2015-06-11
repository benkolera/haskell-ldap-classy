# ldap-classy

This is an attempt to write a safer layer over the top of the [LDAP] C bindings.

This comes in three main parts:

- Providing Types and functions for representing and combining DNs and SearchFilters.
- Providing safe way to serialize these to strings and back.
- Providing some ToLDAPEntry FromLDAPEntry typeclasses for going back and forth between Entries and haskell data types.

## RFCs 

There have been a number of RFCs consulted in the making of the escaping rules:

- [RFC4514] - String Representation of Distinguished Names
- [RFC4512] - Directory Information Models
- [RFC2254] - String Representation of LDAP Search Filters

[LDAP] http://hackage.haskell.org/package/LDAP)

[RFC4514](https://tools.ietf.org/html/rfc4514)

[RFC4512](https://tools.ietf.org/html/rfc4512)

[RFC4515](https://tools.ietf.org/html/rfc4515)
