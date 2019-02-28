At this time the aws js sdk v3 only exports a node and browser client.
Since the types are the same and are _only_ exported in the packages
themselves, to support both versions I can either include both
packages _or_ copy the types here.  I have chose to copy the types
for 2 reasons.

1. I use an exceedingly limited set of the entire KMS API
1. The KMS API has been stable and unchanged since 2014-11-01
1. Given that the aws js sdk v3 was split up, merging them back together seem counter productive.
