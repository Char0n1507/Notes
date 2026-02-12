# Queries

### Return all users

Will even return disabled users

```cypher
MATCH (u:User)
RETURN u;
```

### Return a specific user

```cypher
MATCH (u:User) WHERE u.name = "<USER>@<DOMAIN>" RETURN u
```

### Return a user's group membership

```cql
MATCH p=((n:User {name:"<USER>@<DOMAIN>"})-[r:MemberOf]->(g:Group))
RETURN p
```

### Return all computers

```cypher
MATCH (c:Computer)
RETURN c;
```

### Shortest path to DA from any user

```shellscript
MATCH p=shortestPath((n:User)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|Contains|GPLink|AllowedToDelegate|TrustedBy|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|DCFor*1..]->(m:Group))
WHERE n.enabled = True AND m.objectid ENDS WITH "-512"
RETURN p
```

### Users allowed to WinRM to a computer

```shellscript
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer)
RETURN p2
```

### Find SQL server admins

```shellscript
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer)
RETURN p2
```

### Shortest path from node that contains \<STRING> to any node

With this query, we can find almost any path in the domain

This script search for the shortestPath from any node to any node. In this example, if we manage to compromise Peter, but he doesn't have a path to Domain Admin or a High-Value Target, most likely, we won't get any results using default queries in BloodHound. However, by utilizing this query, we can determine if peter has access to a machine, a user, a group, GPO, or anything in the domain.

```cql
MATCH p = shortestPath((n)-[*1..]->(c))
WHERE n.name =~ '(?i)peter.*' AND NOT c=n
RETURN p
```

### Find specific rights that the Domain Users group should not have

```cql
MATCH p=(g:Group)-
[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(c:Computer)
WHERE g.name STARTS WITH "DOMAIN USERS"
RETURN p
```

### Find all users with a description field that is not blank

```cql
MATCH (u:User)
WHERE u.description IS NOT NULL
RETURN u.name,u.description
```
