# liboidcagent
`liboidcagent` is a go library for requesting OpenID Connect access token
from [`oidc-agent`](https://github.com/indigo-dc/oidc-agent) from within go
applications.

Documentation can be found at
https://indigo-dc.gitbook.io/oidc-agent/api/api-go


## Tests
The testing the library requires a working oidc-agent setup:
```sh
oidc-add <account shortname>
export OIDC_AGENT_ACCOUNT=<account shortname>
export OIDC_AGENT_ISSUER=<issuer of the account>
go test -v
```
